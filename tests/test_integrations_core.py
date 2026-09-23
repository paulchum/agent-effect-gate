"""Real broker/IPC and provider-neutral adapter tests; no mocked SDK certification."""
from __future__ import annotations
import asyncio
import base64
import concurrent.futures
import inspect
import json
import os
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_effect_gate import Broker
from agent_effect_gate.client import GateClient, UnixTransport, read_session_token
from agent_effect_gate.codec import canonical, loads
from agent_effect_gate.integrations.common import GateToolkit, ToolBundle
from agent_effect_gate.ipc import (MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME, PROTOCOL, TransportError,
                                    UnixGateServer, receive_frame, send_frame)
from agent_effect_gate.tool_types import ToolResult


class RecordingTool:
    """Local test adapter, not a third-party SDK or external service."""
    def __init__(self):
        self.calls = []
        self.started = threading.Event()
        self.finish = threading.Event()
        self.wait = False
    def manifest(self): return {'adapter': 'test-recording-v1', 'effect': 'local_code'}
    def prepare(self, arguments, artifact):
        if set(arguments) != {'value'}: raise ValueError('Test schema')
        return dict(arguments)
    def invoke(self, plan, call_id):
        self.calls.append((call_id, plan))
        self.started.set()
        if self.wait: self.finish.wait(2)
        return ToolResult({'value': plan['value']}, str(plan['value']))


class IPCBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.tool = RecordingTool()
        self.broker = Broker(self.directory / 'state.sqlite', b'test-local-key-not-a-real-secret-0000',
                             tools={'compute': self.tool})
        self.policy = {'agents': ['main', 'peer'], 'answer_mode': 'model',
                       'max_requests': 1000, 'max_denials': 1000,
                       'tool_grants': {'compute': {'approval': 'required', 'max_calls': 100}}}
        self.tokens = self.broker.create_task('task', 'tenant', self.policy)
        self.server = UnixGateServer(self.directory / 'gate.sock', self.broker).start()
        self.transport = UnixTransport(self.directory / 'gate.sock', self.tokens['main'])
        self.client = GateClient(self.transport)
        self.kit = GateToolkit(self.client)
    def tearDown(self):
        self.tool.finish.set()
        self.server.stop()
        self.broker.close()
        self.tmp.cleanup()
    def request(self, op, args=None, rid='r1'):
        return self.client.request(op, args or {}, request_id=rid)
    def standing(self):
        policy = dict(self.policy)
        policy['tool_grants'] = {'compute': {'approval': 'standing', 'max_calls': 100}}
        self.broker.replace_policy('task', policy)


class IPCRoundTrips(IPCBase):
    def test_actual_kernel_socket_context_roundtrip(self):
        result = self.request('context')
        self.assertTrue(result['ok'])
        self.assertEqual(result['result']['snapshot']['task_id'], 'task')
    def test_model_cannot_call_control_plane(self):
        for index, op in enumerate(['approve_tool', 'create_task', 'replace_policy', 'revoke_session']):
            result = self.request(op, rid=f'admin-{index}')
            self.assertFalse(result['ok'])
            self.assertEqual(result['error'], 'unknown_operation')
    def test_session_credentials_are_bound_not_in_model_arguments(self):
        result = self.request('context', {'token': self.tokens['peer']})
        self.assertFalse(result['ok'])
    def test_wrong_scoped_token_is_denied(self):
        client = GateClient(UnixTransport(self.directory / 'gate.sock', 'x' * 43))
        self.assertEqual(client.request('context', {}, request_id='bad')['error'], 'unauthorized')
    def test_unicode_session_is_rejected_without_broker_crash(self):
        result = self.broker.handle('\ud800' * 43, {'request_id':'u', 'operation':'context', 'arguments':{}})
        self.assertEqual(result['error'], 'unauthorized')
        self.assertTrue(self.request('context')['ok'])
    def test_foreign_agent_observation_is_denied(self):
        self.standing()
        result = self.client.call_tool('compute', {'value': 'a'}, request_id='work')
        oid = result['result']['observation']['observation_id']
        other = GateClient(UnixTransport(self.directory / 'gate.sock', self.tokens['peer']))
        self.assertFalse(other.request('read_observation', {'observation_id': oid}, request_id='steal')['ok'])
    def test_model_authored_answer_has_broker_notices(self):
        self.assertIsNone(self.request('answer')['result']['answer']['text'])
        result = loads(self.kit.aeg_submit_answer('My own prose', '[]', '[]', 'submit'))
        self.assertTrue(result['ok'])
        answer = self.request('answer', rid='final')['result']['answer']
        self.assertEqual(answer['text'], 'My own prose')
        self.assertFalse(answer['truthfulness_verified'])
    def test_model_cannot_create_a_citation(self):
        result = loads(self.kit.aeg_submit_answer('x', '[{"observation_id":"missing","quote":"x"}]', '[]', 'cite'))
        self.assertFalse(result['ok'])
    def test_artifact_roundtrip(self):
        result = loads(self.kit.aeg_put_artifact('text/plain', base64.b64encode(b'hello').decode(), 'artifact'))
        aid = result['result']['artifact_id']
        actual = loads(self.kit.aeg_read_artifact(aid, 'read'))
        self.assertTrue(actual['ok'])
        self.assertIn(base64.b64encode(b'hello').decode(), canonical(actual).decode())
    def test_ungranted_communication_denied(self):
        result = loads(self.kit.aeg_send_message('peer', 'hello', 'msg'))
        self.assertEqual(result['error'], 'channel_not_allowed')
    def test_fresh_answer_does_not_replay_away_new_notices(self):
        self.kit.aeg_submit_answer('A draft', '[]', '[]', 'draft')
        self.kit.aeg_answer('same-read')
        self.request('not_authorized', rid='deny')
        answer = loads(self.kit.aeg_answer('same-read'))
        self.assertTrue(answer['result']['answer']['notices'])
    def test_no_full_audit_scan_per_framework_request(self):
        before = self.broker.store.verification_stats['full_scans']
        for index in range(50): self.kit.aeg_context(f'view-{index}')
        self.assertEqual(self.broker.store.verification_stats['full_scans'], before)


class RetryAndConcurrency(IPCBase):
    def test_same_logical_id_after_approval_dispatches_once(self):
        first = self.client.call_tool('compute', {'value': 'a'}, request_id='logical')
        self.assertEqual(first['error'], 'approval_required')
        self.assertFalse(self.tool.calls)
        self.broker.approve_tool(first['call_id'], reviewer='human')
        for _ in range(3):
            result = self.client.call_tool('compute', {'value': 'a'}, request_id='logical')
            self.assertEqual(result['result']['state'], 'SUCCEEDED')
        self.assertEqual(len(self.tool.calls), 1)
    def test_changed_args_do_not_create_another_action(self):
        self.client.call_tool('compute', {'value': 'a'}, request_id='logical')
        conflict = self.client.call_tool('compute', {'value': 'b'}, request_id='logical')
        self.assertEqual(conflict['error'], 'request_id_conflict')
        self.assertEqual(self.broker.store.db.execute('SELECT count(*) FROM tool_calls').fetchone()[0], 1)
    def test_client_recreation_preserves_logical_action(self):
        first = self.client.call_tool('compute', {'value': 'a'}, request_id='logical')
        self.broker.approve_tool(first['call_id'], reviewer='human')
        client2 = GateClient(UnixTransport(self.directory / 'gate.sock', self.tokens['main']))
        result = client2.call_tool('compute', {'value': 'a'}, request_id='logical')
        self.assertEqual(result['call_id'], first['call_id'])
        self.assertEqual(len(self.tool.calls), 1)
    def test_parallel_framework_calls_do_not_duplicate_effect(self):
        self.standing()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.client.call_tool('compute', {'value': 'a'}, request_id='parallel'), range(16)))
        self.assertTrue(all(result['ok'] for result in results))
        self.assertEqual(len(self.tool.calls), 1)
    def test_suspended_task_stops_framework_effects(self):
        self.standing()
        self.broker.set_suspended('task', True, operator='human')
        result = self.client.call_tool('compute', {'value': 'a'}, request_id='stop')
        self.assertFalse(result['ok']); self.assertFalse(self.tool.calls)
    def test_standing_task_still_cannot_approve_other_tools(self):
        self.standing()
        result = self.client.call_tool('other', {'value': 'a'}, request_id='other')
        self.assertEqual(result['error'], 'tool_not_allowed')
    def test_async_client_reaches_same_broker(self):
        async def run(): return await self.client.arequest('context', {}, request_id='async')
        self.assertTrue(asyncio.run(run())['ok'])
    def test_cancellation_does_not_create_a_second_dispatch(self):
        self.standing(); self.tool.wait = True
        async def run():
            task = asyncio.create_task(self.client.acall_tool('compute', {'value': 'a'}, request_id='cancel'))
            await asyncio.to_thread(self.tool.started.wait, 2)
            task.cancel()
            try: await task
            except asyncio.CancelledError: pass
            self.tool.finish.set()
            # Same-ID recovery is safe even while original IPC worker finishes.
            for _ in range(20):
                result = await self.client.acall_tool('compute', {'value': 'a'}, request_id='cancel')
                if result['result']['state'] == 'SUCCEEDED': return result
                await asyncio.sleep(.01)
            self.fail('No completed observation')
        self.assertEqual(asyncio.run(run())['result']['state'], 'SUCCEEDED')
        self.assertEqual(len(self.tool.calls), 1)
    def test_expired_approval_remains_denied(self):
        first = self.client.call_tool('compute', {'value': 'a'}, request_id='expire')
        self.broker.approve_tool(first['call_id'], reviewer='human', ttl_seconds=1)
        self.broker.clock = lambda: time.time() + 5
        result = self.client.call_tool('compute', {'value': 'a'}, request_id='expire')
        self.assertEqual(result['error'], 'approval_expired')
        self.assertFalse(self.tool.calls)


class ToolkitContracts(IPCBase):
    def test_all_model_parameters_are_strings_not_credentials(self):
        for function in self.kit.functions():
            signature = inspect.signature(function)
            self.assertNotIn('token', signature.parameters)
            self.assertNotIn('client', signature.parameters)
            self.assertNotIn('approved', signature.parameters)
            self.assertTrue(function.__doc__)
            self.assertIn('request_id', signature.parameters)
            for parameter in signature.parameters.values():
                self.assertIn(parameter.annotation, (str, 'str'))
    def test_async_wrappers_preserve_native_schemas(self):
        for sync, async_fn in zip(self.kit.functions(), self.kit.async_functions()):
            self.assertTrue(inspect.iscoroutinefunction(async_fn))
            self.assertEqual(inspect.signature(sync), inspect.signature(async_fn))
            self.assertEqual(sync.__name__, async_fn.__name__)
    def test_async_tool_wrapper_returns_actual_result(self):
        fn = next(f for f in self.kit.async_functions() if f.__name__ == 'aeg_context')
        self.assertTrue(loads(asyncio.run(fn(request_id='wrapper')))['ok'])
    def test_invalid_json_is_not_sent_as_tool_arguments(self):
        for raw in ['[]', '{', '{"value":1,"value":2}', '{"value":NaN}']:
            self.assertFalse(loads(self.kit.aeg_call_tool('compute', raw, 'invalid'))['ok'])
        self.assertFalse(self.tool.calls)
    def test_answer_json_types_are_checked(self):
        self.assertFalse(loads(self.kit.aeg_submit_answer('x', '{}', '[]', 'bad'))['ok'])
        self.assertFalse(loads(self.kit.aeg_submit_answer('x', '[]', '{}', 'bad2'))['ok'])
    def test_max_length_logical_request_ids_stay_valid(self):
        result = self.client.call_tool('compute', {'value': 'a'}, request_id='x' * 80)
        self.assertEqual(result['error'], 'approval_required')
    def test_inventory_rejects_foreign_tool_even_with_same_name(self):
        objects = tuple(self.kit.functions())
        bundle = ToolBundle(objects, self.kit)
        bundle.assert_inventory(reversed(objects))
        def impostor(request_id): return 'not gated'
        impostor.__name__ = objects[0].__name__
        with self.assertRaises(ValueError): bundle.assert_inventory([impostor, *objects[1:]])
        with self.assertRaises(ValueError): bundle.assert_inventory([*objects, impostor])
        with self.assertRaises(ValueError): bundle.assert_inventory(objects[:-1])
    def test_transport_error_is_explicitly_unknown_and_does_not_retry(self):
        calls = []
        class Broken:
            def exchange(inner, request): calls.append(request); raise TransportError()
        kit = GateToolkit(GateClient(Broken()))
        result = loads(kit.aeg_context('failure'))
        self.assertEqual(result['delivery_outcome'], 'unknown')
        self.assertEqual(len(calls), 1)
    def test_client_repr_redacts_scoped_token(self):
        self.assertNotIn(self.tokens['main'], repr(self.transport))


class IPCFramingAndPermissions(IPCBase):
    def raw(self, value):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.directory / 'gate.sock'))
            send_frame(conn, canonical(value), MAX_REQUEST_FRAME, time.monotonic()+2)
            return loads(receive_frame(conn, MAX_RESPONSE_FRAME, time.monotonic()+2))
    def test_bad_protocol_fails_closed(self):
        self.assertFalse(self.raw({'protocol': 'bad', 'token': self.tokens['main'], 'request': {}})['ok'])
    def test_extra_transport_authority_field_is_denied(self):
        self.assertFalse(self.raw({'protocol': PROTOCOL, 'token': self.tokens['main'], 'request': {}, 'approved': True})['ok'])
    def test_oversized_frame_rejected_before_reading_body(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.directory / 'gate.sock'))
            conn.sendall(struct.pack('!I', MAX_REQUEST_FRAME + 1))
            response = loads(receive_frame(conn, MAX_RESPONSE_FRAME, time.monotonic()+2))
            self.assertFalse(response['ok'])
    def test_server_refuses_to_replace_existing_socket(self):
        with self.assertRaises(ValueError): UnixGateServer(self.directory / 'gate.sock', self.broker)
    def test_server_refuses_world_writable_directory(self):
        parent = self.directory / 'unsafe'; parent.mkdir(); parent.chmod(0o777)
        with self.assertRaises(ValueError): UnixGateServer(parent / 'gate.sock', self.broker)
    def test_server_refuses_symlink_directory(self):
        alias = self.directory / 'alias'; alias.symlink_to(self.directory)
        with self.assertRaises(ValueError): UnixGateServer(alias / 'new.sock', self.broker)
    def test_client_refuses_mismatched_broker_identity(self):
        wrong = UnixTransport(self.directory / 'gate.sock', self.tokens['main'], expected_server_uid=os.getuid()+1)
        with self.assertRaises(TransportError): wrong.exchange({'request_id':'x','operation':'context','arguments':{}})
    def test_os_admission_is_not_bypassed_by_valid_token(self):
        self.server.allowed_uids = frozenset({os.getuid()+1})
        with patch.object(self.broker, 'handle', wraps=self.broker.handle) as dispatch:
            try:
                result = self.request('context')
            except TransportError:
                # The server rejects the UID before reading a frame. Closing a
                # socket with unread client bytes may reset it before the denial
                # frame arrives; either outcome must leave the broker untouched.
                pass
            else:
                self.assertFalse(result['ok'])
                self.assertEqual(result['error'], 'unauthorized_peer')
            dispatch.assert_not_called()
    def test_missing_socket_raises_without_silent_fallback(self):
        transport = UnixTransport(self.directory/'absent.sock', self.tokens['main'])
        with self.assertRaises(TransportError): transport.exchange({'request_id':'x','operation':'context','arguments':{}})
    def test_frame_deadline_bounds_incomplete_input(self):
        a, b = socket.socketpair()
        try:
            started = time.monotonic()
            with self.assertRaises(TimeoutError): receive_frame(a, 100, time.monotonic()+.05)
            self.assertLess(time.monotonic()-started, .5)
        finally: a.close(); b.close()
    def test_private_token_file_and_no_symlink(self):
        path = self.directory / 'session.token'; path.write_text(self.tokens['main']); path.chmod(0o600)
        self.assertEqual(read_session_token(path), self.tokens['main'])
        alias = self.directory / 'alias.token'; alias.symlink_to(path)
        with self.assertRaises(OSError): read_session_token(alias)
        path.chmod(0o644)
        with self.assertRaises(ValueError): read_session_token(path)
    def test_token_file_size_is_bounded(self):
        path = self.directory/'huge.token'; path.write_text('x'*5000); path.chmod(0o600)
        with self.assertRaises(ValueError): read_session_token(path)
    def test_socket_permissions_are_private(self):
        self.assertEqual(stat.S_IMODE((self.directory/'gate.sock').stat().st_mode), 0o600)
    def test_transport_timeouts_reject_nonfinite_or_unbounded_values(self):
        for value in [0, -1, float('nan'), float('inf'), 10000, True, '4']:
            with self.assertRaises(ValueError): UnixTransport(self.directory/'gate.sock', self.tokens['main'], timeout=value)
    def test_server_worker_limit_is_bounded(self):
        for value in [0, 10000, True]:
            with self.assertRaises(ValueError): UnixGateServer(self.directory/'new.sock', self.broker, max_workers=value)
