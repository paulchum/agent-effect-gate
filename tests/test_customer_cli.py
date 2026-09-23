"""Subprocess MCP/CLI integration; no paid APIs or external customer services."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_effect_gate import __version__
from agent_effect_gate.cli import initialize, _broker
from agent_effect_gate.codec import MAX_WIRE_BYTES
from agent_effect_gate.operations import backup_state, restore_state
from agent_effect_gate.reviewer_auth import ReviewerAuth, AuthError

ROOT = Path(__file__).parents[1]
PASSWORD = 'synthetic-reviewer-password-only-for-tests'

class CustomerCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.state = self.root / 'state'
        self.config = self.root / 'config.json'; self.password = self.root / 'password'
        self.password.write_text(PASSWORD + '\n'); self.password.chmod(0o600)
        self.config.write_text(json.dumps({'task_id': 'task', 'tenant_id': 'tenant', 'sources': [],
            'policy': {'agents': ['main'], 'answer_mode': 'model', 'stage': 'deployment', 'local_only': False,
                       'tool_grants': {'docs': {'approval': 'required', 'max_calls': 10}}},
            'tools': [{'id': 'docs', 'kind': 'http_read', 'origin': 'https://docs.python.org', 'path_prefix': '/3', 'query_keys': []}]}))
        self.head = initialize(self.state, self.config, reviewer=('alice', PASSWORD))['audit_head']
    def tearDown(self): self.tmp.cleanup()
    def command(self, command, *args, raw=None):
        return subprocess.run([sys.executable, '-m', 'agent_effect_gate', command, '--state', str(self.state), *map(str, args)],
                              input=raw, capture_output=True, text=True, cwd=ROOT, timeout=30)
    def propose(self):
        broker = _broker(self.state)
        try:
            return broker.handle((self.state / 'sessions/main.token').read_text(), {'request_id': 'prepare', 'operation': 'propose_tool',
                'arguments': {'tool_id': 'docs', 'arguments': {'path': '/3/index.html', 'query': {}}}})['result']['call_id']
        finally: broker.close()
    @staticmethod
    def messages():
        return [ {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'customer-cli-test', 'version': '1'}}},
                 {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                 {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
                 {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'aeg_context', 'arguments': {}}}]
    def test_mcp_stdio_subprocess_handshake_discovery_and_call(self):
        result = self.command('mcp', raw=''.join(json.dumps(m) + '\n' for m in self.messages()))
        self.assertEqual(result.returncode, 0, result.stderr); rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([r['id'] for r in rows], [1, 2, 3]); self.assertEqual(rows[0]['result']['serverInfo']['version'], __version__)
        self.assertFalse(rows[-1]['result']['isError']); self.assertNotIn((self.state / 'sessions/main.token').read_text(), result.stdout)
    def test_stdio_recovers_after_malformed_and_oversized_frames(self):
        raw = '{\n' + 'x' * (MAX_WIRE_BYTES + 32) + '\n' + json.dumps({'jsonrpc': '2.0', 'id': 8, 'method': 'ping'}) + '\n'
        result = self.command('mcp', raw=raw); rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]['error']['code'], -32700); self.assertEqual(rows[1]['error']['code'], -32700); self.assertEqual(rows[2]['result'], {})
    def test_incomplete_final_frame_is_not_executed(self):
        result = self.command('mcp', raw=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}))
        self.assertEqual(json.loads(result.stdout)['error']['code'], -32700)
    def test_sigterm_stops_idle_mcp_cleanly(self):
        process = subprocess.Popen([sys.executable, '-m', 'agent_effect_gate', 'mcp', '--state', str(self.state)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT)
        try:
            process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}) + '\n'); process.stdin.flush()
            self.assertEqual(json.loads(process.stdout.readline())['result'], {})
            process.send_signal(signal.SIGTERM); _, error = process.communicate(timeout=10); self.assertEqual(process.returncode, 0, error)
        finally:
            if process.poll() is None: process.kill(); process.wait()
    def test_cli_typed_reviewer_name_without_login_is_refused(self):
        cid = self.propose(); result = self.command('approve-tool', '--call', cid, '--reviewer', 'alice', raw='')
        self.assertEqual(result.returncode, 2); broker = _broker(self.state)
        try: self.assertEqual(broker.review_tool(cid)['state'], 'PENDING')
        finally: broker.close()
    def test_cli_approval_authenticates_password_and_records_identity(self):
        cid = self.propose(); result = self.command('approve-tool', '--call', cid, '--reviewer', 'alice', '--password-file', self.password)
        self.assertEqual(result.returncode, 0, result.stderr); broker = _broker(self.state)
        try:
            self.assertEqual(broker.store.db.execute('SELECT approver FROM tool_calls WHERE id=?', (cid,)).fetchone()[0], 'alice')
            self.assertEqual(broker.store.db.execute('SELECT count(*) FROM reviewer_sessions').fetchone()[0], 0)
        finally: broker.close()
    def test_cli_break_glass_is_explicit_and_not_a_forged_login(self):
        cid = self.propose(); result = self.command('approve-tool', '--call', cid, '--reviewer', 'claimed-name', '--break-glass')
        self.assertEqual(result.returncode, 0, result.stderr); broker = _broker(self.state)
        try:
            self.assertEqual(broker.store.db.execute('SELECT approver FROM tool_calls WHERE id=?', (cid,)).fetchone()[0], 'breakglass')
            self.assertEqual(broker.store.db.execute("SELECT count(*) FROM audit WHERE kind='operator_break_glass'").fetchone()[0], 1)
        finally: broker.close()
    def test_restore_revokes_reviewer_sessions(self):
        broker = _broker(self.state); token, _ = ReviewerAuth(broker.store).login('alice', PASSWORD); head = broker.store.verify(); broker.close()
        backup_state(self.state, self.root / 'backup', anchor=head)
        restore_state(self.root / 'backup', self.root / 'restored', anchor=head, operator='operator')
        broker = _broker(self.root / 'restored')
        try:
            self.assertEqual(broker.store.db.execute('SELECT count(*) FROM reviewer_sessions').fetchone()[0], 0)
            with self.assertRaises(AuthError): ReviewerAuth(broker.store).authenticate(token)
        finally: broker.close()
    def test_reviewer_provisioning_is_atomic_with_initialization(self):
        destination = self.root / 'bad-state'
        with self.assertRaises(ValueError): initialize(destination, self.config, reviewer=('alice', 'too-short'))
        self.assertFalse(destination.exists()); self.assertEqual(list(self.root.glob('.aeg-init-*')), [])
    def test_compaction_preserves_historical_audit_anchor(self):
        anchor = self.root / 'anchor.json'; anchor.write_text(json.dumps(self.head))
        result = self.command('compact', '--anchor', anchor); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['audit_history_deleted'])
        self.assertEqual(self.command('audit', '--anchor', anchor).returncode, 0)
    def test_model_run_requires_egress_consent_before_network(self):
        prompt = self.root / 'prompt.txt'; prompt.write_text('Summarize the current task.')
        result = self.command('model-run', '--model', 'customer-selected-model', '--prompt-file', prompt)
        self.assertEqual(result.returncode, 2); self.assertNotIn('Traceback', result.stderr)
