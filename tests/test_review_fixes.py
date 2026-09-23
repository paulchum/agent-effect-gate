"""Defensive regression coverage for the eight supplied review findings.

All service errors and external effects are local fakes. No customer endpoints,
provider credentials, network writes or exploit payloads are used.
"""
from __future__ import annotations

import ast
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_effect_gate import Broker, Rejected
from agent_effect_gate.broker import SCHEMAS
from agent_effect_gate.cli import _broker, initialize, main
from agent_effect_gate.codec import canonical, digest, IntegrityError
from agent_effect_gate.http_tools import HTTPRead, HTTPTransport, HTTPUpload
from agent_effect_gate.operations import doctor, review_doctor
from agent_effect_gate.reviewer_auth import Reviewer
from agent_effect_gate.reviewer_service import ReviewerService
from agent_effect_gate.review_preview import upload_preview
from agent_effect_gate.sandbox import LinuxSandbox
from agent_effect_gate.store import Store
from agent_effect_gate.tool_types import ToolResult
from support import Case, KEY, policy


class Echo:
    def __init__(self, effect='local_code', *, raises=False, body='serializes    objects'):
        self.effect, self.raises, self.body, self.calls = effect, raises, body, 0
    def manifest(self): return {'adapter': 'review-test-v1', 'effect': self.effect}
    def prepare(self, arguments, artifact): return dict(arguments)
    def invoke(self, prepared, call_id):
        self.calls += 1
        if self.raises:
            raise TimeoutError('synthetic-private-error-must-not-escape')
        return ToolResult({'stdout': self.body}, self.body, True)


class ReviewCoreFixes(Case):
    def setup_tool(self, effect='local_code', *, raises=False, body='serializes    objects', **changes):
        self.tool = Echo(effect, raises=raises, body=body)
        self.b._tools = {'echo': self.tool}
        grant = {'approval': 'required' if effect == 'network_write' else 'standing',
                 'max_calls': 100, 'allow_argument_egress': True}
        self.p = policy(answer_mode='model', fields=[], local_only=False, max_denials=20,
                        tool_grants={'echo': grant}, **changes)
        self.b.replace_policy('task', self.p)
        self.cid = self.call('propose_tool', {'tool_id': 'echo', 'arguments': {}})['result']['call_id']
        return self.cid

    def execute(self, *, rid='execute'):
        return self.call('execute_tool', {'call_id': self.cid}, request_id=rid)

    def test_failed_read_is_failed_and_does_not_disclose_error_or_replay(self):
        self.setup_tool('network_read', raises=True)
        result = self.execute()
        self.assertEqual(result['result']['state'], 'FAILED')
        self.assertNotIn('synthetic-private-error', json.dumps(result))
        self.assertEqual(self.execute()['result']['state'], 'FAILED')
        self.assertEqual(self.tool.calls, 1)
        self.assertEqual(self.b.store.db.execute("SELECT count(*) FROM tool_calls WHERE state IN ('UNKNOWN','DISPATCHING')").fetchone()[0], 0)

    def test_status_poll_identifiers_are_validated_before_sql_queries(self):
        self.b.replace_policy('task', policy(max_denials=1000))
        for operation, key in [('execute_tool', 'call_id'), ('execute_release', 'proposal_id')]:
            for value in [None, True, False, 42, 2**100, 3.14, [], {}, {'id': 'fake'}, '', '../x']:
                with self.subTest(operation=operation, value=value):
                    result = self.call(operation, {key: value})
                    self.assertEqual(result['error'], 'invalid_identifier')
                    self.assertFalse(self.b._failed)
        self.assertTrue(self.call('context')['ok'])

    def test_external_write_exception_remains_unknown(self):
        self.setup_tool('network_write', raises=True)
        self.b.approve_tool(self.cid, reviewer='alice')
        self.assertEqual(self.execute()['result']['state'], 'UNKNOWN')
        self.assertEqual(self.execute()['result']['state'], 'UNKNOWN')
        self.assertEqual(self.tool.calls, 1)

    def test_reconciliation_requires_suspension_evidence_and_uncertain_state(self):
        self.setup_tool('network_write', raises=True)
        self.b.approve_tool(self.cid, reviewer='alice'); self.execute()
        with self.assertRaisesRegex(Rejected, 'reconciliation_requires_suspension'):
            self.b.reconcile_effect('tool', self.cid, outcome='failed', operator='ops', evidence_reference='case-123')
        self.b.set_suspended('task', True, operator='ops')
        with self.assertRaises(Rejected):
            self.b.reconcile_effect('tool', self.cid, outcome='failed', operator='ops', evidence_reference='  ')
        result = self.b.reconcile_effect('tool', self.cid, outcome='failed', operator='ops', evidence_reference='case-123')
        self.assertEqual(result['state'], 'FAILED')
        with self.assertRaisesRegex(Rejected, 'effect_not_uncertain'):
            self.b.reconcile_effect('tool', self.cid, outcome='failed', operator='ops', evidence_reference='case-123')
        self.b.set_suspended('task', False, operator='ops')
        self.assertEqual(self.execute()['result']['state'], 'FAILED')
        self.assertEqual(self.tool.calls, 1)
        row = self.b.store.db.execute("SELECT agent,details FROM audit WHERE kind='effect_reconciled'").fetchone()
        self.assertEqual(row['agent'], 'ops')
        self.assertEqual(json.loads(row['details'])['evidence_reference_sha256'], digest(b'case-123'))
        self.assertNotIn('case-123', row['details'])
        self.assertNotIn('reconcile_effect', SCHEMAS)
        self.assertNotIn('reconcile', SCHEMAS)

    def test_interrupted_dispatch_can_be_reconciled_without_invocation(self):
        self.setup_tool()
        with self.b.store.transaction() as db:
            db.execute("UPDATE tool_calls SET state='DISPATCHING' WHERE id=?", (self.cid,))
        self.b.set_suspended('task', True, operator='ops')
        result = self.b.reconcile_effect('tool', self.cid, outcome='failed', operator='ops', evidence_reference='local-log-1')
        self.assertEqual(result['state'], 'FAILED')
        self.assertEqual(self.tool.calls, 0)

    def test_failed_release_reconciliation_is_terminal(self):
        pid = self.proposal(approved=True)
        with self.b.store.transaction() as db:
            db.execute("UPDATE proposals SET state='UNKNOWN' WHERE id=?", (pid,))
        self.b.set_suspended('task', True, operator='ops')
        self.b.reconcile_effect('release', pid, outcome='failed', operator='ops', evidence_reference='receipt-log-1')
        self.b.set_suspended('task', False, operator='ops')
        result = self.call('execute_release', {'proposal_id': pid})
        self.assertEqual(result['result']['state'], 'FAILED')
        self.assertEqual(self.deliveries, [])
        with self.assertRaisesRegex(Rejected, 'proposal_not_pending'):
            self.b.approve_release(pid, reviewer='alice')

    def test_twenty_citation_corrections_do_not_open_breaker(self):
        self.setup_tool()
        obs = self.execute()['result']['observation_id']
        for i in range(20):
            result = self.call('submit_answer', {'text': 'A claim', 'citations': [
                {'observation_id': obs, 'quote': 'serializes objects'}], 'limitations': []})
            self.assertEqual(result['error'], 'citation_quote_mismatch')
        self.assertEqual(self.b.store.db.execute("SELECT suspended,denials FROM tasks WHERE id='task'").fetchone()[:], (0, 0))
        self.assertTrue(self.call('submit_answer', {'text': 'A claim', 'citations': [
            {'observation_id': obs, 'quote': 'serializes    objects'}], 'limitations': []})['ok'])

    def test_request_conflicts_preserve_original_and_do_not_open_breaker(self):
        self.setup_tool()
        request = {'tool_id': 'echo', 'arguments': {'q': 'original'}}
        original = self.call('propose_tool', request, request_id='step-1')
        for i in range(20):
            self.assertEqual(self.call('propose_tool', {'tool_id': 'echo', 'arguments': {'q': str(i)}},
                                       request_id='step-1')['error'], 'request_id_conflict')
        self.assertEqual(self.call('propose_tool', request, request_id='step-1'), original)
        self.assertEqual(self.b.store.db.execute("SELECT suspended,denials FROM tasks WHERE id='task'").fetchone()[:], (0, 0))

    def test_real_authorization_violations_still_open_breaker(self):
        self.setup_tool()
        for _ in range(20):
            self.assertEqual(self.call('propose_tool', {'tool_id': 'outside-grant', 'arguments': {}})['error'], 'tool_not_allowed')
        self.assertEqual(self.b.store.db.execute("SELECT suspended,denials FROM tasks WHERE id='task'").fetchone()[:], (1, 20))

    def test_finished_polls_store_hashes_not_observations_and_use_reads(self):
        self.setup_tool(body='x' * 60_000)
        first = self.execute()
        head = self.b.store.verify()
        for i in range(300):
            self.assertEqual(self.execute(rid=f'poll-{i}'), first)
        size = self.b.store.db.execute('SELECT sum(length(response)) FROM requests').fetchone()[0]
        self.assertLess(size, 4096)
        self.assertEqual(self.tool.calls, 1)
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM observations').fetchone()[0], 1)
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM read_request_hashes').fetchone()[0], 300)
        self.assertEqual(self.b.store.db.execute("SELECT requests,read_requests FROM tasks WHERE id='task'").fetchone()[:], (2, 300))
        self.assertEqual(self.b.store.verify(), head)

    def test_same_id_completed_poll_and_read_quota_remain_bounded(self):
        self.setup_tool(max_read_requests=2)
        result = self.execute()
        self.assertEqual(self.execute(), result)
        self.assertEqual(self.execute(), result)
        before = self.b.store.db.total_changes
        self.assertEqual(self.execute()['error'], 'read_budget_exhausted')
        self.assertEqual(self.b.store.db.total_changes, before)
        self.assertEqual(self.tool.calls, 1)

    def test_legacy_cached_observations_are_compacted_on_reopen(self):
        self.setup_tool(body='x' * 60_000)
        result = self.execute()
        with self.b.store.transaction() as db:
            db.execute("DELETE FROM schema_migrations WHERE version='compact-live-cache-v1'")
            db.execute("UPDATE requests SET response=? WHERE id='execute'", (canonical(result).decode(),))
        self.b.close()
        self.b = Broker(self.path, KEY, clock=self.clock, tools={'echo': self.tool})
        cached = json.loads(self.b.store.db.execute("SELECT response FROM requests WHERE id='execute'").fetchone()[0])
        self.assertNotIn('observation', cached['result'])
        self.assertEqual(self.execute()['result']['observation']['text'], 'x' * 60_000)
        self.assertEqual(self.tool.calls, 1)

    def test_expired_tool_is_renewable_under_same_request_and_not_a_denial(self):
        self.setup_tool('network_write')
        self.assertEqual(self.execute()['error'], 'approval_required')
        self.b.approve_tool(self.cid, reviewer='alice')
        self.clock.advance(301)
        expired = self.execute()
        self.assertEqual(expired['error'], 'approval_expired')
        self.assertTrue(expired['retryable'])
        self.b.approve_tool(self.cid, reviewer='bob')
        self.assertEqual(self.execute()['result']['state'], 'SUCCEEDED')
        self.assertEqual(self.tool.calls, 1)
        self.assertEqual(self.b.store.db.execute("SELECT denials FROM tasks WHERE id='task'").fetchone()[0], 0)
        self.assertEqual(self.b.store.db.execute("SELECT agent FROM audit WHERE kind='tool_approval_renewed'").fetchone()[0], 'bob')

    def test_expired_release_is_renewable(self):
        pid = self.proposal(approved=True)
        self.clock.advance(301)
        self.assertEqual(self.call('execute_release', {'proposal_id': pid}, request_id='dispatch')['error'], 'approval_expired')
        self.b.approve_release(pid, reviewer='alice')
        self.assertEqual(self.call('execute_release', {'proposal_id': pid}, request_id='dispatch')['result']['state'], 'DELIVERED')
        self.assertEqual(len(self.deliveries), 1)

    def test_renewal_cannot_extend_live_approval_or_revive_revocation(self):
        self.setup_tool('network_write')
        self.b.approve_tool(self.cid, reviewer='alice')
        with self.assertRaisesRegex(Rejected, 'proposal_not_pending'):
            self.b.approve_tool(self.cid, reviewer='bob')
        self.b.revoke_tool(self.cid, reviewer='alice')
        self.clock.advance(301)
        with self.assertRaisesRegex(Rejected, 'proposal_not_pending'):
            self.b.approve_tool(self.cid, reviewer='bob')
        self.assertEqual(self.tool.calls, 0)

    def test_renewal_authenticates_the_previous_approval(self):
        self.setup_tool('network_write')
        self.b.approve_tool(self.cid, reviewer='alice')
        self.clock.advance(301)
        self.b.store.db.execute("UPDATE tool_calls SET approval_mac='invalid' WHERE id=?", (self.cid,))
        with self.assertRaises(IntegrityError):
            self.b.approve_tool(self.cid, reviewer='bob')

    def test_expired_requests_return_to_reviewer_pending_queue(self):
        self.setup_tool('network_write')
        reviewer = Reviewer('alice', ('task',), 'session', 'csrf')
        service = ReviewerService(self.b)
        self.b.approve_tool(self.cid, reviewer='alice')
        self.assertEqual(service.queue(reviewer)['items'], [])
        before = service.detail(reviewer, 'tool', self.cid)
        self.clock.advance(301)
        detail = service.detail(reviewer, 'tool', self.cid)
        self.assertTrue(detail['approval_expired']); self.assertTrue(detail['can_approve'])
        self.assertNotEqual(before['review_token'], detail['review_token'])
        self.assertEqual(service.overview(reviewer)['pending'], 1)
        self.assertEqual(service.queue(reviewer)['items'][0]['id'], self.cid)
        with self.assertRaisesRegex(Rejected, 'review_changed_refresh_required'):
            service.decide(reviewer, 'tool', self.cid, 'approve', before['review_token'])
        self.assertEqual(service.decide(reviewer, 'tool', self.cid, 'approve', detail['review_token'])['state'], 'APPROVED')


class ReviewStoreFixes(Case):
    def test_startup_full_scan_does_not_hold_writer_lock_and_verifies_new_tail(self):
        entered, resume = threading.Event(), threading.Event()
        failures, opened = [], []
        original = Store.verify
        def held_scan(store, anchor=None):
            head = original(store, anchor)
            entered.set()
            if not resume.wait(5): raise AssertionError('Startup test did not resume')
            return head
        def start():
            try: opened.append(Broker(self.path, KEY))
            except BaseException as exc: failures.append(exc)
        with patch.object(Store, 'verify', held_scan):
            thread = threading.Thread(target=start); thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.b.store.db.execute('PRAGMA busy_timeout=30')
                self.assertTrue(self.call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='})['ok'])
            finally:
                resume.set(); thread.join(5)
        self.assertFalse(thread.is_alive()); self.assertEqual(failures, [])
        try:
            self.assertEqual(opened[0].store._anchor, self.b.store._anchor)
            self.assertTrue(self.call('context')['ok'])
        finally:
            for broker in opened: broker.close()

    def test_busy_before_dispatch_does_not_poison_broker_or_spend_quota(self):
        other = sqlite3.connect(self.path, isolation_level=None)
        self.b.store.db.execute('PRAGMA busy_timeout=20')
        before = self.b.store.db.total_changes
        try:
            other.execute('BEGIN IMMEDIATE')
            response = self.call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='}, request_id='busy')
            self.assertEqual(response['error'], 'broker_busy'); self.assertTrue(response['retryable'])
            self.assertFalse(self.b._failed); self.assertEqual(self.b.store.db.total_changes, before)
            self.assertEqual(self.b.host_view(self.tokens['main'], 'context')['error'], 'broker_busy')
        finally:
            other.rollback(); other.close()
        self.assertTrue(self.call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='}, request_id='busy')['ok'])
        self.assertTrue(self.call('context')['ok'])

    def test_busy_after_dispatch_does_not_replay_or_stop_unrelated_reads(self):
        other = sqlite3.connect(self.path, isolation_level=None)
        self.b.store.db.execute('PRAGMA busy_timeout=20')
        tool = Echo()
        self.b._tools = {'echo': tool}
        self.b.replace_policy('task', policy(answer_mode='model', fields=[], tool_grants={'echo': {'approval': 'standing', 'max_calls': 1}}))
        cid = self.call('propose_tool', {'tool_id': 'echo', 'arguments': {}})['result']['call_id']
        invoke = tool.invoke
        def hold(*args):
            result = invoke(*args)
            other.execute('BEGIN IMMEDIATE')
            return result
        try:
            with patch.object(tool, 'invoke', side_effect=hold):
                result = self.call('execute_tool', {'call_id': cid})
            self.assertEqual(result['error'], 'post_dispatch_audit_unavailable')
            self.assertFalse(result['retry_dispatch']); self.assertFalse(self.b._failed)
        finally:
            other.rollback(); other.close()
        self.assertTrue(self.call('context')['ok'])
        self.assertEqual(self.call('execute_tool', {'call_id': cid})['result']['state'], 'DISPATCHING')
        self.assertEqual(tool.calls, 1)


class ReviewRuntimeFixes(Case):
    def test_runtime_pauses_unknown_post_dispatch_without_another_model_step(self):
        from agent_effect_gate.runtime import run
        class Model:
            calls = 0
            def propose(self, context, last):
                self.calls += 1
                return {'request_id': 'uncertain', 'operation': 'execute_tool',
                        'arguments': {'call_id': 'call_uncertain'}}
        model = Model()
        with patch.object(self.b, 'handle', return_value={
                'ok': False, 'error': 'post_dispatch_audit_unavailable',
                'delivery_outcome': 'unknown', 'retryable': False, 'retry_dispatch': False}):
            result = run(model, self.b, self.tokens['main'], max_steps=5)
        self.assertEqual(model.calls, 1)
        self.assertEqual(result['runtime']['reason'], 'awaiting_reconciliation')
        self.assertEqual(result['runtime']['pending_request']['request_id'], 'uncertain')


class FailedReadReadiness(unittest.TestCase):
    def test_failed_builtin_http_read_does_not_block_production_doctor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / 'state'; config = root / 'config.json'
            config.write_text(json.dumps({'task_id': 'task', 'tenant_id': 'tenant', 'sources': [],
                'policy': {'agents': ['main'], 'stage': 'deployment', 'answer_mode': 'model',
                           'local_only': False, 'tool_grants': {'docs': {'approval': 'standing',
                           'max_calls': 5, 'allow_argument_egress': True}}},
                'tools': [{'id': 'docs', 'kind': 'http_read', 'origin': 'https://docs.example.com',
                           'path_prefix': '/3', 'query_keys': []}]}))
            initial = initialize(state, config)
            broker = _broker(state)
            try:
                token = (state / 'sessions/main.token').read_text()
                prepared = broker.handle(token, {'request_id': 'prepare', 'operation': 'propose_tool',
                    'arguments': {'tool_id': 'docs', 'arguments': {'path': '/3/index.html', 'query': {}}}})
                cid = prepared['result']['call_id']
                with patch.object(HTTPTransport, 'request', side_effect=OSError('synthetic connection failure')) as request:
                    reply = broker.handle(token, {'request_id': 'execute', 'operation': 'execute_tool',
                        'arguments': {'call_id': cid}})
                request.assert_called_once()
                self.assertEqual(reply['result']['state'], 'FAILED')
                anchor = dict(broker.store._anchor)
            finally:
                broker.close()
            readiness = doctor(state, production=True, anchor=anchor)
            failed = [c['code'] for c in readiness['checks'] if c['required'] and not c['ok']]
            self.assertEqual(failed, ['non_root_service_user'] if os.geteuid() == 0 else [], readiness)
            self.assertEqual(readiness['uncertain_effects'], 0)


class CredentialFreeReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.state = self.root / 'state'; self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'task_id': 'task', 'tenant_id': 'tenant', 'sources': [],
            'policy': {'agents': ['main'], 'stage': 'deployment', 'answer_mode': 'model', 'local_only': False,
                       'tool_grants': {'upload': {'approval': 'required', 'max_calls': 5}}},
            'tools': [{'id': 'upload', 'kind': 'http_upload', 'origin': 'https://api.example.com',
                       'path': '/v1/notes', 'credential_env': 'REVIEW_TEST_TOOL_TOKEN'}]}))
        self.env = patch.dict(os.environ, {'REVIEW_TEST_TOOL_TOKEN': 'synthetic-tool-token-original'}); self.env.start()
        initialize(self.state, self.config, reviewer=('alice', 'synthetic-test-only-long-reviewer-password'))
        self.executor = _broker(self.state)
        self.token = (self.state / 'sessions/main.token').read_text()
        self.reviewer = Reviewer('alice', ('task',), 'session', 'csrf')
        self.note = b'Customer 4411. Internal margin: 62%. <script>not executable</script>\n'
        def call(rid, op, args):
            return self.executor.handle(self.token, {'request_id': rid, 'operation': op, 'arguments': args})
        self.call = call
        aid = call('artifact', 'put_artifact', {'media_type': 'text/plain', 'data_b64': base64.b64encode(self.note).decode()})['result']['artifact_id']
        self.cid = call('prepare', 'propose_tool', {'tool_id': 'upload', 'arguments': {'artifact_id': aid}})['result']['call_id']
        self.env.stop()
        self.no_credentials = patch.dict(os.environ, {}, clear=True); self.no_credentials.start()
        self.review_broker = _broker(self.state, adapters=False)
        self.service = ReviewerService(self.review_broker)
    def tearDown(self):
        self.review_broker.close(); self.executor.close(); self.no_credentials.stop(); self.tmp.cleanup()

    def test_review_approves_without_credentials_but_executor_rechecks_rotation(self):
        detail = self.service.detail(self.reviewer, 'tool', self.cid)
        self.assertEqual(self.review_broker._tools, {})
        self.assertTrue(detail['binding_current'])
        self.assertEqual(detail['adapter_validation'], 'dispatch_recheck_required')
        self.assertEqual(self.service.decide(self.reviewer, 'tool', self.cid, 'approve', detail['review_token'])['state'], 'APPROVED')
        self.executor._tools = {'upload': HTTPUpload(HTTPTransport('https://api.example.com', credential='synthetic-rotated-token'), '/v1/notes')}
        with patch.object(HTTPTransport, 'request') as request:
            response = self.call('execute', 'execute_tool', {'call_id': self.cid})
        self.assertEqual(response['error'], 'approval_binding_changed'); request.assert_not_called()

    def test_upload_preview_keeps_exact_bytes_and_hash(self):
        detail = self.service.detail(self.reviewer, 'tool', self.cid)
        preview = detail['payload_preview']
        self.assertEqual(preview['text'], self.note.decode())
        self.assertEqual(preview['byte_length'], len(self.note))
        self.assertEqual(preview['sha256'], digest(self.note))
        self.assertEqual(base64.b64decode(preview['data_b64']), self.note)
        self.assertEqual(detail['request_sha256'], digest(canonical(detail['prepared_request'])))
        self.assertEqual(self.review_broker.review_tool(self.cid)['payload_preview'], preview)

    def test_binary_payload_is_not_lossily_decoded_and_bad_digest_fails(self):
        plan = {'payload_b64': base64.b64encode(b'\xff\x00').decode(), 'payload_sha256': digest(b'\xff\x00'), 'media_type': 'application/octet-stream'}
        preview = upload_preview(plan)
        self.assertEqual(preview['encoding'], 'binary'); self.assertIsNone(preview['text'])
        with self.assertRaises(IntegrityError): upload_preview({**plan, 'payload_sha256': '0' * 64})

    def test_review_readiness_has_no_credentials_or_effect_health_dependency(self):
        self.executor.set_suspended('task', True, operator='ops')
        result = review_doctor(self.state)
        self.assertTrue(result['ready'], result)
        self.assertTrue(result['review_only'])
        with self.assertRaises(ValueError): doctor(self.state)

    def test_actual_review_cli_does_not_load_execution_adapters(self):
        observed = []
        def run(app, **kwargs):
            observed.append(app.broker._tools)
            self.assertTrue(ReviewerService(app.broker).detail(self.reviewer, 'tool', self.cid)['binding_current'])
        with patch.dict(sys.modules, {'uvicorn': SimpleNamespace(run=run)}):
            self.assertEqual(main(['review', '--state', str(self.state)]), 0)
        self.assertEqual(observed, [{}])


class SandboxIdentityConfiguration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        (self.root / '.aeg-rootfs.json').write_text('{}')
    def tearDown(self): self.tmp.cleanup()
    def mappings(self, path, *args, **kwargs):
        if str(path) in {'/etc/subuid', '/etc/subgid'}: return 'broker:100000:65536\n'
        raise AssertionError('Unexpected mapping file')
    def configured(self):
        return LinuxSandbox(str(self.root))

    @patch('agent_effect_gate.sandbox.shutil.which', return_value='/usr/bin/mapping-helper')
    @patch('agent_effect_gate.sandbox.pwd.getpwuid', return_value=SimpleNamespace(pw_name='broker'))
    @patch('agent_effect_gate.sandbox.os.getegid', return_value=1000)
    @patch('agent_effect_gate.sandbox.os.geteuid', return_value=1000)
    def test_nonroot_uses_distinct_subordinate_ids_and_drops_groups(self, *mocks):
        with patch.object(Path, 'read_text', autospec=True, side_effect=self.mappings):
            sandbox = self.configured()
        self.assertEqual(sandbox.worker_uid, 100000); self.assertEqual(sandbox.worker_gid, 100000)
        self.assertTrue(sandbox.manifest()['host_identity_separated'])
        data = {'stdout': 'ok', 'stderr': '', 'returncode': 0, 'stop_reason': None, 'output_errors': {}, 'outputs': {}}
        with patch('agent_effect_gate.sandbox.capture', return_value={'returncode': 0, 'stop_reason': None, 'stdout': canonical(data)}) as run:
            self.assertTrue(sandbox.invoke({'language': 'python', 'code': 'print(1)', 'inputs': {}, 'outputs': []}, 'check').succeeded)
        argv, payload = run.call_args.args
        self.assertIn('--map-users=1000,0,1', argv); self.assertIn('--map-users=100000,1,1', argv)
        self.assertIn('--map-groups=100000,1,1', argv); self.assertIn('--setgroups=allow', argv)
        self.assertNotIn('--map-root-user', argv)
        self.assertEqual(json.loads(payload)['worker_namespace_uid'], 1)
        self.assertTrue(json.loads(payload)['clear_supplementary_groups'])

    @patch('agent_effect_gate.sandbox.os.getegid', return_value=1000)
    @patch('agent_effect_gate.sandbox.os.geteuid', return_value=1000)
    def test_same_broker_uid_is_rejected(self, *mocks):
        with self.assertRaisesRegex(ValueError, 'distinct'):
            LinuxSandbox(str(self.root), worker_uid=1000, worker_gid=1000)

    @patch('agent_effect_gate.sandbox.shutil.which', return_value=None)
    @patch('agent_effect_gate.sandbox.pwd.getpwuid', return_value=SimpleNamespace(pw_name='broker'))
    @patch('agent_effect_gate.sandbox.os.getegid', return_value=1000)
    @patch('agent_effect_gate.sandbox.os.geteuid', return_value=1000)
    def test_missing_mapping_helpers_fail_closed(self, *mocks):
        with patch.object(Path, 'read_text', autospec=True, side_effect=self.mappings):
            with self.assertRaisesRegex(ValueError, 'newuidmap/newgidmap'):
                self.configured()

    @patch('agent_effect_gate.sandbox.pwd.getpwuid', return_value=SimpleNamespace(pw_name='broker'))
    @patch('agent_effect_gate.sandbox.os.getegid', return_value=1000)
    @patch('agent_effect_gate.sandbox.os.geteuid', return_value=1000)
    def test_missing_delegation_fails_closed(self, *mocks):
        with patch.object(Path, 'read_text', return_value='other:100000:65536\n'):
            with self.assertRaisesRegex(ValueError, 'delegated'):
                self.configured()

    def test_default_deny_profile_excludes_reviewed_kernel_interfaces(self):
        source = (Path(__file__).parents[1] / 'agent_effect_gate/_sandbox_worker.py').read_text()
        module = ast.parse(source)
        names = next(ast.literal_eval(node.value) for node in module.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'ALLOWED_SYSCALLS' for target in node.targets))
        excluded = {'fsopen', 'open_tree', 'name_to_handle_at', 'msgget', 'memfd_create', 'personality',
                    'kcmp', 'mbind', 'setxattr', 'landlock_create_ruleset', 'socket', 'unshare', 'setns',
                    'bpf', 'io_uring_setup', 'setuid', 'setresuid', 'setgid', 'setresgid', 'setgroups'}
        self.assertFalse(set(names) & excluded)
        self.assertIn('lib.seccomp_init(deny_action)', source)
        self.assertIn('(~ordinary)', source)


if __name__ == '__main__':
    unittest.main()
