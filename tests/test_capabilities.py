"""Cross-lineage integration regressions; synthetic data, no paid provider calls."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_effect_gate import Broker
from agent_effect_gate.client import GateClient, UnixTransport
from agent_effect_gate.codec import Rejected, canonical, digest, loads
from agent_effect_gate.ipc import TransportError, UnixGateServer
from agent_effect_gate.mcp_server import MCPServer, ScopedMCPServer
from agent_effect_gate.model_connector import OpenAIResponsesAdapter
from agent_effect_gate.models import RunCheckpoint, run_client
from agent_effect_gate.runtime import run, _TrustedHostClient
from agent_effect_gate.tool_types import ToolResult
from support import Case, KEY, policy


class SyntheticTool:
    def __init__(self, *, unknown=False):
        self.invocations = []
        self.unknown = unknown

    def manifest(self):
        return {'adapter': 'capability-fixture-v1', 'effect': 'local_code'}

    def prepare(self, arguments, artifact):
        if set(arguments) != {'value'}:
            raise Rejected('invalid_schema')
        return dict(arguments)

    def invoke(self, plan, call_id):
        self.invocations.append((call_id, plan))
        if self.unknown:
            raise RuntimeError('synthetic uncertain external outcome')
        return ToolResult({'value': plan['value']}, str(plan['value']))


class ScriptedAdapter:
    """A real local deterministic adapter, not a live-model certification."""
    def __init__(self, *, binding='fixture'):
        self.binding = binding
        self.index = 0
        self.calls = 0

    def export_state(self):
        return {'binding': self.binding, 'index': self.index}

    def import_state(self, state):
        if state['binding'] != self.binding:
            raise Rejected('checkpoint_configuration_mismatch')
        self.index = state['index']

    def propose(self, context, last):
        self.calls += 1
        i = self.index
        self.index += 1
        if i == 0:
            return {'request_id': 'script-prepare', 'operation': 'propose_tool',
                    'arguments': {'tool_id': 'compute', 'arguments': {'value': 'synthetic'}}}
        if i == 1:
            return {'request_id': 'script-execute', 'operation': 'execute_tool',
                    'arguments': {'call_id': last['result']['call_id']}}
        return {'request_id': 'script-final', 'operation': 'submit_answer',
                'arguments': {'text': 'Synthetic local result.', 'citations': [],
                              'limitations': ['Local scripted validation, not a live model.']}}


class CapabilityCase(Case):
    def setUp(self):
        super().setUp()
        self.tool = SyntheticTool()
        self.b._tools = {'compute': self.tool}
        self.configure()
        self.checkpoint = RunCheckpoint(Path(self.directory.name) / 'run.json')

    def configure(self, *, approval='required', **limits):
        p = policy(answer_mode='model', fields=[],
                   tool_grants={'compute': {'approval': approval, 'max_calls': 50}}, **limits)
        self.b.replace_policy('task', p)

    def approval_pause(self):
        adapter = ScriptedAdapter()
        result = run(adapter, self.b, self.tokens['main'], checkpoint=self.checkpoint)
        self.assertEqual(result['runtime']['reason'], 'approval_required')
        self.assertEqual(adapter.calls, 2)
        self.assertEqual(len(self.tool.invocations), 0)
        pending = self.checkpoint.load()['pending_request']
        return pending


class CapabilityQuotaTests(CapabilityCase):
    def test_mutable_retries_have_independent_durable_quota(self):
        self.configure(max_requests=2, max_read_requests=1, max_retry_requests=2)
        proposal = self.call('propose_tool', {'tool_id': 'compute', 'arguments': {'value': 'x'}})['result']
        args = {'call_id': proposal['call_id']}
        self.assertEqual(self.call('execute_tool', args, request_id='execute')['error'], 'approval_required')
        for _ in range(2):
            self.assertEqual(self.call('execute_tool', args, request_id='execute')['error'], 'approval_required')
        before = self.b.store.db.total_changes
        head = self.b.store.verify()
        for _ in range(20):
            self.assertEqual(self.call('execute_tool', args, request_id='execute')['error'], 'retry_budget_exhausted')
        self.assertEqual(self.b.store.db.total_changes, before)
        self.assertEqual(self.b.store.verify(), head)
        self.assertTrue(self.call('context')['ok'])
        self.assertEqual(tuple(self.b.store.db.execute('SELECT requests,read_requests,retry_requests,denials,suspended FROM tasks').fetchone()), (2, 1, 2, 0, 0))
        self.b.close(); self.b = Broker(self.path, KEY, clock=self.clock, tools={'compute': self.tool})
        self.assertEqual(self.call('execute_tool', args, request_id='execute')['error'], 'retry_budget_exhausted')

    def test_plan_bytes_are_capped_without_security_denial(self):
        self.configure(max_tool_plan_bytes=1024)
        successes = 0
        for _ in range(10):
            result = self.call('propose_tool', {'tool_id': 'compute', 'arguments': {'value': 'é' * 140}})
            if not result['ok']:
                self.assertEqual(result['error'], 'tool_plan_quota_exceeded')
                break
            successes += 1
        self.assertGreater(successes, 0)
        self.assertLess(successes, 10)
        size = self.b.store.db.execute('SELECT sum(length(CAST(plan AS BLOB))) FROM tool_calls').fetchone()[0]
        self.assertLessEqual(size, 1024)
        self.assertEqual(self.b.store.db.execute('SELECT denials FROM tasks').fetchone()[0], 0)

    def test_completed_execution_cache_retains_no_observation_body(self):
        self.configure(approval='standing')
        proposal = self.call('propose_tool', {'tool_id': 'compute', 'arguments': {'value': 'private fixture'}})['result']
        args = {'call_id': proposal['call_id']}
        executed = self.call('execute_tool', args, request_id='execute')
        self.assertTrue(executed['ok'])
        stored = self.b.store.db.execute('SELECT response FROM requests WHERE id="execute"').fetchone()[0]
        self.assertEqual(json.loads(stored), {'ok': True})
        self.assertEqual(self.call('execute_tool', args, request_id='execute')['result']['state'], 'SUCCEEDED')
        self.assertEqual(len(self.tool.invocations), 1)

    def test_all_three_budget_dimensions_are_in_snapshot(self):
        snapshot = self.b.host_view(self.tokens['main'], 'context')['result']['snapshot']
        self.assertEqual(set(snapshot['control']['budgets']), {'actions', 'reads', 'retries'})
        self.assertEqual(len(snapshot['scope_id']), 64)

    def test_invalid_new_policy_limits_are_rejected(self):
        for changes in ({'max_retry_requests': 0}, {'max_retry_requests': True}, {'max_tool_plan_bytes': 1023}):
            with self.assertRaises(Rejected):
                self.configure(**changes)

    def test_same_successful_write_does_not_spend_retry_quota(self):
        self.configure(max_retry_requests=1)
        for _ in range(20):
            self.assertTrue(self.call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='}, request_id='same')['ok'])
        self.assertEqual(self.b.store.db.execute('SELECT retry_requests FROM tasks').fetchone()[0], 0)


class CapabilityCheckpointTests(CapabilityCase):
    def test_approval_resume_preserves_exact_envelope_and_invokes_once(self):
        pending = self.approval_pause()
        self.assertEqual(pending['request_id'], 'script-execute')
        self.b.approve_tool(pending['arguments']['call_id'], reviewer='fixture-reviewer')
        resumed = ScriptedAdapter()
        result = run(resumed, self.b, self.tokens['main'], checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['result']['answer']['status'], 'submitted')
        self.assertEqual(resumed.calls, 1)
        self.assertEqual(len(self.tool.invocations), 1)
        self.assertTrue(self.checkpoint.load()['complete'])
        self.assertIsNone(self.checkpoint.load()['pending_request'])

    def test_resume_completed_run_makes_no_provider_or_tool_calls(self):
        self.configure(approval='standing')
        run(ScriptedAdapter(), self.b, self.tokens['main'], checkpoint=self.checkpoint)
        resumed = ScriptedAdapter()
        result = run(resumed, self.b, self.tokens['main'], checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['result']['answer']['status'], 'submitted')
        self.assertEqual(resumed.calls, 0)
        self.assertEqual(len(self.tool.invocations), 1)

    def test_pending_action_resumes_after_new_action_budget_is_exhausted(self):
        self.configure(max_requests=2)
        pending = self.approval_pause()
        self.b.approve_tool(pending['arguments']['call_id'], reviewer='fixture-reviewer')
        resumed = ScriptedAdapter()
        result = run(resumed, self.b, self.tokens['main'], checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['runtime']['reason'], 'request_budget_exhausted')
        self.assertEqual(resumed.calls, 0)
        self.assertEqual(len(self.tool.invocations), 1)

    def test_unknown_outcome_pauses_and_resume_does_not_redispatch(self):
        self.configure(approval='standing')
        self.tool.unknown = True
        first = ScriptedAdapter()
        result = run(first, self.b, self.tokens['main'], checkpoint=self.checkpoint)
        self.assertEqual(result['runtime']['reason'], 'awaiting_reconciliation')
        pending = self.checkpoint.load()['pending_request']
        resumed = ScriptedAdapter()
        again = run(resumed, self.b, self.tokens['main'], checkpoint=self.checkpoint, resume=True)
        self.assertEqual(again['runtime']['reason'], 'awaiting_reconciliation')
        self.assertEqual(self.checkpoint.load()['pending_request'], pending)
        self.assertEqual((first.calls, resumed.calls, len(self.tool.invocations)), (2, 0, 1))

    def test_noncheckpointed_customer_runtime_also_stops_on_unknown(self):
        self.configure(approval='standing')
        self.tool.unknown = True
        adapter = ScriptedAdapter()
        result = run(adapter, self.b, self.tokens['main'])
        self.assertEqual(result['runtime']['reason'], 'awaiting_reconciliation')
        self.assertEqual(adapter.calls, 2)

    def test_approval_resume_survives_broker_and_adapter_restart(self):
        pending = self.approval_pause()
        self.b.close(); self.b = Broker(self.path, KEY, clock=self.clock, tools={'compute': self.tool})
        self.b.approve_tool(pending['arguments']['call_id'], reviewer='fixture-reviewer')
        result = run(ScriptedAdapter(), self.b, self.tokens['main'], checkpoint=RunCheckpoint(self.checkpoint.path), resume=True)
        self.assertEqual(result['result']['answer']['status'], 'submitted')
        self.assertEqual(len(self.tool.invocations), 1)

    def test_transport_response_loss_preserves_original_request(self):
        self.configure(approval='standing')
        local = _TrustedHostClient(self.b, self.tokens['main'])
        class Lossy:
            view = local.view
            def request(self, operation, arguments, *, request_id):
                result = local.request(operation, arguments, request_id=request_id)
                if operation == 'execute_tool':
                    raise TransportError()
                return result
        first = ScriptedAdapter()
        result = run_client(first, Lossy(), checkpoint=self.checkpoint)
        self.assertEqual(result['delivery_outcome'], 'unknown')
        self.assertEqual(self.checkpoint.load()['pending_request']['request_id'], 'script-execute')
        resumed = ScriptedAdapter()
        result = run_client(resumed, local, checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['result']['answer']['status'], 'submitted')
        self.assertEqual((len(self.tool.invocations), resumed.calls), (1, 1))

    def test_busy_broker_retains_pending_request_instead_of_new_model_call(self):
        self.configure(approval='standing')
        local = _TrustedHostClient(self.b, self.tokens['main'])
        class Busy:
            view = local.view
            def request(self, operation, arguments, *, request_id):
                if operation == 'execute_tool':
                    return {'ok': False, 'error': 'gate_busy', 'retryable': True}
                return local.request(operation, arguments, request_id=request_id)
        result = run_client(ScriptedAdapter(), Busy(), checkpoint=self.checkpoint)
        self.assertEqual(result['error'], 'gate_busy')
        self.assertEqual(self.checkpoint.load()['pending_request']['request_id'], 'script-execute')
        result = run_client(ScriptedAdapter(), local, checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['result']['answer']['status'], 'submitted')
        self.assertEqual(len(self.tool.invocations), 1)

    def test_step_pause_recovers_adapter_position(self):
        first = run(ScriptedAdapter(), self.b, self.tokens['main'], checkpoint=self.checkpoint, max_steps=1)
        self.assertEqual(first['runtime']['reason'], 'runtime_step_budget_exhausted')
        self.assertEqual(self.checkpoint.load()['adapter']['index'], 1)
        result = run(ScriptedAdapter(), self.b, self.tokens['main'], checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['runtime']['reason'], 'approval_required')
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM tool_calls').fetchone()[0], 1)

    def test_existing_checkpoint_requires_explicit_resume(self):
        self.approval_pause()
        original = self.checkpoint.path.read_bytes()
        adapter = ScriptedAdapter()
        result = run_client(adapter, _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint)
        self.assertEqual(result['error'], 'existing_checkpoint_requires_resume')
        self.assertEqual(adapter.calls, 0)
        self.assertEqual(self.checkpoint.path.read_bytes(), original)

    def test_changed_adapter_configuration_fails_before_dispatch(self):
        self.approval_pause()
        adapter = ScriptedAdapter(binding='different')
        result = run_client(adapter, _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['error'], 'checkpoint_configuration_mismatch')
        self.assertEqual((adapter.calls, len(self.tool.invocations)), (0, 0))

    def test_same_task_label_in_different_broker_fails_scope_binding(self):
        self.approval_pause()
        with tempfile.TemporaryDirectory() as directory:
            other = Broker(Path(directory) / 'other.sqlite', secrets.token_bytes(32))
            try:
                token = other.create_task('task', 'tenant', policy(answer_mode='model', fields=[]))['main']
                adapter = ScriptedAdapter()
                result = run_client(adapter, _TrustedHostClient(other, token), checkpoint=self.checkpoint, resume=True)
                self.assertEqual(result['error'], 'checkpoint_scope_mismatch')
                self.assertEqual(adapter.calls, 0)
            finally:
                other.close()

    def test_other_agent_cannot_resume_same_checkpoint(self):
        self.approval_pause()
        result = run_client(ScriptedAdapter(), _TrustedHostClient(self.b, self.tokens['worker']), checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['error'], 'checkpoint_scope_mismatch')

    def test_suspension_blocks_checkpoint_resume(self):
        self.approval_pause()
        self.b.set_suspended('task', True, operator='fixture')
        adapter = ScriptedAdapter()
        result = run_client(adapter, _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['error'], 'task_suspended')
        self.assertEqual(adapter.calls, 0)

    def test_failed_checkpoint_write_cannot_dispatch_prepared_action(self):
        with patch.object(self.checkpoint, 'save', side_effect=OSError('synthetic private disk detail')):
            result = run_client(ScriptedAdapter(), _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint)
        self.assertEqual(result['error'], 'model_or_checkpoint_failed')
        self.assertNotIn('private disk detail', json.dumps(result))
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM tool_calls').fetchone()[0], 0)

    def test_single_writer_lease_blocks_concurrent_run(self):
        adapter = ScriptedAdapter()
        with self.checkpoint.lease():
            result = run_client(adapter, _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint)
        self.assertEqual(result['error'], 'checkpoint_busy')
        self.assertEqual(adapter.calls, 0)

    def test_no_provider_call_when_new_action_budget_exhausted(self):
        self.configure(max_requests=1)
        self.artifact(b'x')
        adapter = ScriptedAdapter()
        before = self.b.store.db.total_changes
        result = run(adapter, self.b, self.tokens['main'], checkpoint=self.checkpoint)
        self.assertEqual(result['runtime']['reason'], 'request_budget_exhausted')
        self.assertEqual(adapter.calls, 0)
        self.assertEqual(self.b.store.db.total_changes, before)

    def test_checkpointed_host_views_do_not_consume_read_quota(self):
        self.approval_pause()
        self.assertEqual(self.b.store.db.execute('SELECT read_requests FROM tasks').fetchone()[0], 0)

    def test_resume_without_checkpoint_is_rejected(self):
        with self.assertRaises(ValueError):
            run_client(ScriptedAdapter(), object(), resume=True)

    def test_missing_resume_file_is_rejected(self):
        result = run_client(ScriptedAdapter(), _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['error'], 'checkpoint_not_found')

    def test_checkpoint_file_permissions_are_private(self):
        self.approval_pause()
        self.assertEqual(self.checkpoint.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.checkpoint.path.with_name('run.json.lock').stat().st_mode & 0o777, 0o600)

    def test_checkpoint_symlinks_and_hardlinks_are_rejected(self):
        self.approval_pause()
        linked = self.checkpoint.path.with_name('linked.json')
        linked.symlink_to(self.checkpoint.path)
        with self.assertRaises(ValueError): RunCheckpoint(linked)
        linked.unlink()
        os.link(self.checkpoint.path, linked)
        with self.assertRaises(ValueError): RunCheckpoint(linked)

    def test_changed_checkpoint_permissions_fail_closed(self):
        self.approval_pause()
        self.checkpoint.path.chmod(0o644)
        result = run_client(ScriptedAdapter(), _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['error'], 'model_or_checkpoint_failed')
        self.assertEqual(len(self.tool.invocations), 0)

    def test_legacy_checkpoint_format_is_not_silently_reinterpreted(self):
        self.approval_pause()
        value = self.checkpoint.load(); value['format'] = 'aeg-model-run-v1'
        self.checkpoint.save(value)
        result = run_client(ScriptedAdapter(), _TrustedHostClient(self.b, self.tokens['main']), checkpoint=self.checkpoint, resume=True)
        self.assertEqual(result['error'], 'checkpoint_format_requires_manual_migration')

    def test_checkpoint_does_not_store_scoped_token_or_admin_key(self):
        self.approval_pause()
        raw = self.checkpoint.path.read_bytes()
        self.assertNotIn(self.tokens['main'].encode(), raw)
        self.assertNotIn(KEY, raw)


class CapabilityIPCAndMCPTests(CapabilityCase):
    def test_scoped_views_are_metered_and_host_view_is_not_exported(self):
        server = UnixGateServer(Path(self.directory.name) / 'gate.sock', self.b).start()
        try:
            client = GateClient(UnixTransport(server.path, self.tokens['main']))
            self.assertTrue(client.view('context')['ok'])
            self.assertEqual(self.b.store.db.execute('SELECT read_requests FROM tasks').fetchone()[0], 1)
            self.assertEqual(client.request('host_view', {'operation': 'context'}, request_id='host-bypass')['error'], 'unknown_operation')
        finally:
            server.stop()

    def test_scoped_mcp_uses_customer_protocol_and_schema(self):
        server = UnixGateServer(Path(self.directory.name) / 'gate.sock', self.b).start()
        try:
            client = GateClient(UnixTransport(server.path, self.tokens['main']))
            scoped, local = ScopedMCPServer(client), MCPServer(self.b, self.tokens['main'])
            names = []
            for mcp in (scoped, local):
                init = mcp.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'fixture', 'version': '1'}}})
                self.assertEqual(init['result']['protocolVersion'], '2025-11-25')
                mcp.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                tools = mcp.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})['result']['tools']
                names.append([t['name'] for t in tools])
                self.assertNotIn('aeg_host_view', names[-1])
                self.assertNotIn('aeg_approve_tool', names[-1])
            self.assertEqual(names[0], names[1])
        finally:
            server.stop()


class CapabilityMigrationTests(CapabilityCase):
    def test_separate_counter_counters_and_read_fingerprints_are_preserved_once(self):
        self.artifact(b'x')
        request = {'request_id': 'old-read', 'operation': 'inbox', 'arguments': {}}
        sha = digest(canonical(request))
        with self.b.store.transaction() as db:
            db.execute('DELETE FROM schema_migrations')
            db.execute('ALTER TABLE tasks DROP COLUMN read_requests')
            db.execute('ALTER TABLE tasks DROP COLUMN retry_requests')
            db.execute('CREATE TABLE usage(task TEXT PRIMARY KEY, reads INTEGER, retries INTEGER)')
            db.execute("INSERT INTO usage VALUES('task',4,2)")
            db.execute('CREATE TABLE read_receipts(task TEXT, agent TEXT, id TEXT, request_sha256 TEXT, PRIMARY KEY(task,agent,id))')
            db.execute('INSERT INTO read_receipts VALUES(?,?,?,?)', ('task', 'main', 'old-read', sha))
            db.execute('CREATE TABLE human_sessions(token_hash TEXT)')
            db.execute("INSERT INTO human_sessions VALUES('expired-session')")
            db.execute('CREATE TABLE human_users(enabled INTEGER)')
            db.execute('INSERT INTO human_users VALUES(1)')
        old_audit = [tuple(row) for row in self.b.store.db.execute('SELECT * FROM audit')]
        self.b.close(); self.b = Broker(self.path, KEY, clock=self.clock, tools={'compute': self.tool})
        self.assertEqual(tuple(self.b.store.db.execute('SELECT requests,read_requests,retry_requests FROM tasks').fetchone()), (1, 4, 2))
        self.assertEqual(self.b.store.db.execute('SELECT request_sha256 FROM read_request_hashes WHERE id="old-read"').fetchone()[0], sha)
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM human_sessions').fetchone()[0], 0)
        self.assertEqual(self.b.store.db.execute('SELECT enabled FROM human_users').fetchone()[0], 0)
        self.assertEqual([tuple(row) for row in self.b.store.db.execute('SELECT * FROM audit')][:len(old_audit)], old_audit)
        head = self.b.store.verify()
        self.b.close(); self.b = Broker(self.path, KEY, clock=self.clock, tools={'compute': self.tool})
        self.assertEqual(self.b.store.verify(), head)
        self.assertEqual(tuple(self.b.store.db.execute('SELECT requests,read_requests,retry_requests FROM tasks').fetchone()), (1, 4, 2))


class CapabilityConnectorState(unittest.TestCase):
    def adapter(self, **kwargs):
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'synthetic-private-api-key-' * 3}):
            return OpenAIResponsesAdapter(model='operator-selected-model', prompt='A synthetic task.',
                                          allow_provider_egress=True, **kwargs)

    def test_exported_adapter_state_has_no_provider_credential_or_prompt(self):
        adapter = self.adapter()
        encoded = json.dumps(adapter.export_state())
        self.assertNotIn('synthetic-private-api-key', encoded)
        self.assertNotIn('A synthetic task.', encoded)
        adapter.import_state(adapter.export_state())

    def test_resume_rejects_changed_provider_configuration(self):
        adapter = self.adapter()
        state = adapter.export_state(); state['model'] = 'different-model'
        with self.assertRaises(Rejected): adapter.import_state(state)

    def test_checkpoint_does_not_remove_explicit_egress_requirement(self):
        with self.assertRaises(ValueError):
            OpenAIResponsesAdapter(model='m', prompt='fixture', allow_provider_egress=False)


class CapabilityBackupTests(unittest.TestCase):
    def test_backup_and_guarded_restore_include_default_checkpoints(self):
        from agent_effect_gate.cli import initialize, _broker
        from agent_effect_gate.operations import backup_state, restore_state
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            config = directory / 'config.json'
            config.write_text(json.dumps({'task_id': 'task', 'tenant_id': 'fixture', 'sources': [], 'tools': [],
                'policy': {'agents': ['main'], 'answer_mode': 'model'}}))
            state = directory / 'state'
            initialize(state, config)
            (state / 'runs').mkdir(mode=0o700)
            checkpoint = RunCheckpoint(state / 'runs/main.json')
            class AnswerAdapter(ScriptedAdapter):
                def propose(self, context, last):
                    return {'request_id': 'final', 'operation': 'submit_answer', 'arguments': {
                        'text': 'Synthetic answer.', 'citations': [], 'limitations': ['fixture']}}
            broker = _broker(state)
            token = (state / 'sessions/main.token').read_text()
            try:
                result = run(AnswerAdapter(), broker, token, checkpoint=checkpoint)
                self.assertEqual(result['result']['answer']['status'], 'submitted')
                head = broker.store.verify()
            finally:
                broker.close()
            before = checkpoint.path.read_bytes()
            backup = directory / 'backup'
            result = backup_state(state, backup, anchor=head)
            self.assertEqual(result['run_checkpoints'], 1)
            self.assertFalse(result['external_checkpoints_included'])
            manifest = json.loads((backup / 'backup.json').read_text())['manifest']
            self.assertIn('runs/main.json', manifest['files'])
            self.assertNotIn('runs/main.json.lock', manifest['files'])
            restored = directory / 'restored'
            result = restore_state(backup, restored, anchor=head, operator='fixture')
            self.assertTrue(result['all_tasks_suspended'])
            self.assertEqual(result['run_checkpoints'], 1)
            self.assertEqual((restored / 'runs/main.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
