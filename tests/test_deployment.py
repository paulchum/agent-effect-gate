"""Customer deployment regressions. All fixtures are local and synthetic."""
from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_effect_gate import Broker, IntegrityError, __version__
from agent_effect_gate.cli import _broker, initialize
from agent_effect_gate.codec import Rejected, canonical
from agent_effect_gate.configuration import read_config
from agent_effect_gate.http_tools import HTTPTransport
from agent_effect_gate.operations import backup_state, doctor, read_anchor, restore_state
from agent_effect_gate.protected import read_private, state_lease

ROOT = Path(__file__).resolve().parents[1]


class Deployment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / 'state'
        self.config = self.root / 'config.json'
        self.spec = json.loads((ROOT / 'deploy/local.json').read_text())
        self.write_config()
        self.initial = initialize(self.state, self.config, production=True)
        self.head = self.initial['audit_head']
        self.anchor = self.root / 'anchor.json'
        self.anchor.write_bytes(canonical(self.head))

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self):
        self.config.write_bytes(canonical(self.spec))

    def command(self, *args, raw=None):
        return subprocess.run([sys.executable, '-m', 'agent_effect_gate', *map(str, args)],
                              input=raw, capture_output=True, text=True, cwd=ROOT, timeout=15)

    def request(self, operation='context', arguments=None, request_id='context-1'):
        return canonical({'request_id': request_id, 'operation': operation, 'arguments': arguments or {}})

    def test_version_matches_metadata_source(self):
        import tomllib
        config = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        self.assertIn('version', config['project']['dynamic'])
        result = self.command('--version')
        self.assertEqual(result.stdout.strip(), f'agent-effect-gate {__version__}')

    def test_validate_config_does_not_invoke_transports(self):
        with patch.object(HTTPTransport, 'request', side_effect=AssertionError('must not send')):
            config, tools = read_config(ROOT / 'deploy/research.json', production=True)
        self.assertEqual(list(tools), ['python_docs'])
        self.assertEqual(config['policy']['stage'], 'deployment')

    def test_unknown_tool_grant_rejected_before_creating_state(self):
        self.spec['policy']['tool_grants'] = {'missing': {'approval': 'required', 'max_calls': 1}}
        self.write_config()
        target = self.root / 'invalid'
        with self.assertRaises(ValueError):
            initialize(target, self.config)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob('.aeg-init-*')))

    def test_duplicate_source_does_not_leave_partial_state(self):
        source = {'id': 's', 'version': 'v1', 'origin': 'synthetic', 'document': {}}
        self.spec['sources'] = [source, source]
        self.write_config()
        target = self.root / 'invalid'
        with self.assertRaises(Exception):
            initialize(target, self.config)
        self.assertFalse(target.exists())

    def test_invalid_policy_preserves_existing_empty_directory(self):
        self.spec['policy']['stage'] = []
        self.write_config()
        target = self.root / 'empty'
        target.mkdir(mode=0o755)
        with self.assertRaises(Rejected):
            initialize(target, self.config)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_failed_staging_is_cleaned(self):
        target = self.root / 'failed'
        with patch('agent_effect_gate.cli._write_private', side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):
                initialize(target, self.config)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob('.aeg-init-*')))

    def test_existing_empty_directory_becomes_private(self):
        target = self.root / 'empty'
        target.mkdir(mode=0o755)
        initialize(target, self.config)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_production_rejects_testing_stage(self):
        self.spec['policy']['stage'] = 'testing'
        self.write_config()
        with self.assertRaises(ValueError):
            read_config(self.config, production=True)

    def test_production_rejects_loopback(self):
        self.spec = json.loads((ROOT / 'deploy/research.json').read_text())
        self.spec['tools'][0].update(origin='http://127.0.0.1:8123', allow_loopback=True)
        self.write_config()
        read_config(self.config)
        with self.assertRaises(ValueError):
            read_config(self.config, production=True)

    def test_local_profile_cannot_grant_network(self):
        self.spec = json.loads((ROOT / 'deploy/research.json').read_text())
        self.spec['policy']['local_only'] = True
        self.write_config()
        with self.assertRaises(ValueError):
            read_config(self.config)

    def test_standing_read_needs_egress_authority(self):
        self.spec = json.loads((ROOT / 'deploy/research.json').read_text())
        self.spec['policy']['tool_grants']['python_docs']['approval'] = 'standing'
        self.write_config()
        with self.assertRaises(ValueError):
            read_config(self.config)
        self.spec['policy']['tool_grants']['python_docs']['allow_argument_egress'] = True
        self.write_config()
        read_config(self.config, production=True)

    def test_standing_upload_rejected(self):
        self.spec['policy'].update(local_only=False, tool_grants={'upload': {'approval': 'standing', 'max_calls': 1}})
        self.spec['tools'] = [{'id': 'upload', 'kind': 'http_upload', 'origin': 'https://example.com', 'path': '/upload'}]
        self.write_config()
        with self.assertRaises(ValueError):
            read_config(self.config)

    def test_state_directory_permissions_rejected_not_silently_repaired(self):
        self.state.chmod(0o755)
        with self.assertRaises(ValueError):
            _broker(self.state)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o755)

    def test_database_permissions_rejected_not_silently_repaired(self):
        path = self.state / 'state.sqlite'
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            _broker(self.state)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_sessions_directory_permissions_rejected(self):
        (self.state / 'sessions').chmod(0o755)
        with self.assertRaises(ValueError):
            _broker(self.state)

    def test_parent_symlink_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(ValueError):
            _broker(alias)

    def test_hardlinked_key_rejected(self):
        os.link(self.state / 'admin.key', self.root / 'key-alias')
        with self.assertRaises(ValueError):
            _broker(self.state)

    def test_fifo_private_read_rejected_without_blocking(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            read_private(fifo)

    def test_dangling_sidecar_rejected(self):
        (self.state / 'state.sqlite-wal').symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError):
            _broker(self.state)

    def test_anchor_accepts_raw_and_command_envelope(self):
        self.assertEqual(read_anchor(self.anchor), self.head)
        self.anchor.write_bytes(canonical(self.initial))
        self.assertEqual(read_anchor(self.anchor), self.head)

    def test_invalid_anchor_is_rejected(self):
        for value in [{'seq': -1, 'mac': '0' * 64}, {'seq': True, 'mac': '0' * 64}, {'seq': 0, 'mac': 'no'}, []]:
            with self.subTest(value=value):
                self.anchor.write_bytes(canonical(value))
                with self.assertRaises((ValueError, Rejected)):
                    read_anchor(self.anchor)

    def test_audit_works_without_rotated_tool_credentials(self):
        (self.state / 'tools.json').write_bytes(canonical([{'id': 'repo', 'kind': 'github_code_search',
            'repositories': ['test/repo'], 'credential_env': 'AEG_TEST_MISSING_CREDENTIAL'}]))
        with patch.dict(os.environ, {}, clear=True):
            broker = _broker(self.state, adapters=False)
            broker.close()
            with self.assertRaises(ValueError):
                _broker(self.state)

    def test_backup_preserves_key_sessions_and_audit(self):
        backup = self.root / 'backup'
        before = (self.state / 'state.sqlite').read_bytes()
        report = backup_state(self.state, backup, anchor=self.head)
        self.assertTrue(report['backed_up'])
        self.assertFalse(report['encrypted'])
        self.assertEqual(report['audit_head'], self.head)
        self.assertEqual((backup / 'admin.key').read_bytes(), (self.state / 'admin.key').read_bytes())
        self.assertEqual((backup / 'sessions/main.token').read_bytes(), (self.state / 'sessions/main.token').read_bytes())
        self.assertEqual((self.state / 'state.sqlite').read_bytes(), before)
        self.assertTrue((backup / 'backup.json').is_file())
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)

    def test_backup_refuses_active_cli_lease(self):
        with state_lease(self.state):
            with self.assertRaises(BlockingIOError):
                backup_state(self.state, self.root / 'backup')
        self.assertFalse((self.root / 'backup').exists())

    def test_backup_never_overwrites_destination(self):
        backup = self.root / 'backup'
        backup.mkdir()
        with self.assertRaises(ValueError):
            backup_state(self.state, backup)

    def test_backup_cannot_be_nested_in_state(self):
        with self.assertRaises(ValueError):
            backup_state(self.state, self.state / 'backup')

    def test_restore_requires_external_anchor(self):
        backup_state(self.state, self.root / 'backup')
        with self.assertRaises(ValueError):
            restore_state(self.root / 'backup', self.root / 'restored', anchor=None, operator='operator')

    def test_restore_suspends_tasks_and_preserves_session_identity(self):
        backup = self.root / 'backup'
        backup_state(self.state, backup)
        restored = self.root / 'restored'
        report = restore_state(backup, restored, anchor=self.head, operator='operator')
        self.assertTrue(report['all_tasks_suspended'])
        self.assertGreater(report['audit_head']['seq'], self.head['seq'])
        self.assertEqual((restored / 'admin.key').read_bytes(), (self.state / 'admin.key').read_bytes())
        broker = _broker(restored)
        try:
            result = broker.handle((restored / 'sessions/main.token').read_text(), self.request())
            self.assertTrue(result['result']['snapshot']['control']['suspended'])
        finally:
            broker.close()

    def test_restore_revokes_pending_tool_approvals(self):
        self.state = self.root / 'research'
        initialize(self.state, ROOT / 'deploy/research.json', production=True)
        broker = _broker(self.state)
        try:
            token = (self.state / 'sessions/main.token').read_text()
            response = broker.handle(token, self.request('propose_tool', {'tool_id': 'python_docs',
                'arguments': {'path': '/3/library/json.html', 'query': {}}}))
            call = response['result']['call_id']
            broker.approve_tool(call, reviewer='operator')
            head = broker.store.verify()
        finally:
            broker.close()
        backup_state(self.state, self.root / 'backup')
        restored = self.root / 'restored'
        report = restore_state(self.root / 'backup', restored, anchor=head, operator='operator')
        self.assertEqual(report['tool_approvals_revoked'], 1)
        broker = _broker(restored)
        try:
            self.assertEqual(broker.review_tool(call)['state'], 'REVOKED')
        finally:
            broker.close()

    def test_restore_rejects_snapshot_older_than_external_anchor(self):
        backup_state(self.state, self.root / 'backup')
        broker = _broker(self.state)
        try:
            broker.handle((self.state / 'sessions/main.token').read_text(), self.request('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='}))
            newer = broker.store.verify()
        finally:
            broker.close()
        with self.assertRaises(IntegrityError):
            restore_state(self.root / 'backup', self.root / 'restored', anchor=newer, operator='operator')
        self.assertFalse((self.root / 'restored').exists())
        self.assertFalse(list(self.root.glob('.aeg-restore-*')))

    def test_restore_rejects_changed_backup_config(self):
        backup = self.root / 'backup'
        backup_state(self.state, backup)
        (backup / 'tools.json').write_text('[{}]')
        with self.assertRaises(IntegrityError):
            restore_state(backup, self.root / 'restored', anchor=self.head, operator='operator')
        self.assertFalse((self.root / 'restored').exists())

    def test_restore_rejects_unrecorded_backup_sidecars(self):
        backup = self.root / 'backup'
        backup_state(self.state, backup)
        extra = backup / 'state.sqlite-wal'
        extra.touch(mode=0o600)
        with self.assertRaises(IntegrityError):
            restore_state(backup, self.root / 'restored', anchor=self.head, operator='operator')

    def test_doctor_no_network_or_model_invocations(self):
        with patch.object(HTTPTransport, 'request', side_effect=AssertionError('no network')):
            result = doctor(self.state, anchor=self.head)
        self.assertTrue(result['ready'], result)
        self.assertFalse(result['network_endpoints_probed'])
        self.assertEqual(result['audit_head'], self.head)

    def test_production_doctor_requires_external_anchor(self):
        result = doctor(self.state, production=True)
        self.assertFalse(result['ready'])
        self.assertIn({'code': 'external_anchor_supplied', 'ok': False, 'required': True}, result['checks'])

    def test_doctor_detects_suspended_task(self):
        broker = _broker(self.state)
        try:
            broker.set_suspended('customer-task', True, operator='operator')
        finally:
            broker.close()
        self.assertFalse(doctor(self.state, anchor=self.head)['ready'])

    def test_errors_are_structured_without_raw_exception_or_traceback(self):
        (self.state / 'admin.key').chmod(0o644)
        result = self.command('audit', '--state', self.state)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stderr)['ok'])
        self.assertNotIn(str(self.state), result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_doctor_rejects_missing_session_file(self):
        (self.state / 'sessions/main.token').unlink()
        self.assertFalse(doctor(self.state, anchor=self.head)['ready'])

    def test_doctor_rejects_revoked_session(self):
        broker = _broker(self.state)
        try:
            broker.revoke_session((self.state / 'sessions/main.token').read_text(), operator='operator')
        finally:
            broker.close()
        self.assertFalse(doctor(self.state, anchor=self.head)['ready'])

    def test_production_serve_rejects_missing_anchor_before_reading_actions(self):
        result = self.command('serve', '--state', self.state, '--agent', 'main', '--production', raw=self.request().decode())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def _start_server(self):
        process = subprocess.Popen([sys.executable, '-m', 'agent_effect_gate', 'serve', '--state', str(self.state), '--agent', 'main'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        process.stdin.write(self.request() + b'\n')
        process.stdin.flush()
        self.assertTrue(select.select([process.stdout], [], [], 10)[0])
        self.assertTrue(json.loads(process.stdout.readline())['ok'])
        return process

    def test_sigterm_exits_idle_server_cleanly(self):
        process = self._start_server()
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stderr, b'')

    def test_sigterm_exits_partial_json_frame_without_hanging(self):
        process = self._start_server()
        process.stdin.write(b'{"request_id":')
        process.stdin.flush()
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stderr, b'')

    def test_jsonl_process_accepts_final_frame_without_newline(self):
        result = self.command('serve', '--state', self.state, '--agent', 'main', raw=self.request().decode())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])

    def test_http_origin_validation_is_strict(self):
        for origin in [None, [], ' https://example.com', 'https://example.com\n', 'https://example.com:0']:
            with self.subTest(origin=origin):
                with self.assertRaises(ValueError):
                    HTTPTransport(origin)
