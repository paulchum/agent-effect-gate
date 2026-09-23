import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CLI(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name) / 'protected'
        r = self.command('init', '--config', str(ROOT / 'examples/local_task.json'))
        self.assertEqual(r.returncode, 0, r.stderr)

    def tearDown(self): self.directory.cleanup()

    def command(self, command, *args, input=None):
        prefix = [sys.executable]
        if os.environ.get('AEG_TEST_COVERAGE') == '1':
            prefix += ['-m', 'coverage', 'run', '--parallel-mode', '--branch', '--source=agent_effect_gate']
        return subprocess.run(prefix + ['-m', 'agent_effect_gate', command,
                               '--state', str(self.state), *args], input=input,
                              cwd=ROOT, capture_output=True, text=True, timeout=20)

    def test_jsonl_process_returns_evidence_and_missing_data(self):
        r = self.command('serve', '--agent', 'main', input='{"request_id":"one","operation":"answer","arguments":{}}\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        answer = json.loads(r.stdout)['result']['answer']
        self.assertEqual(len(answer['fields'][0]['value']), 2)
        self.assertIsNone(answer['fields'][1]['value'])
        self.assertFalse(answer['evidence_complete'])

    def test_control_plane_method_unavailable_over_agent_pipe(self):
        r = self.command('serve', '--agent', 'main', input='{"request_id":"one","operation":"approve_release","arguments":{}}\n')
        self.assertEqual(json.loads(r.stdout)['error'], 'unknown_operation')

    def test_duplicate_json_key_rejected_by_process(self):
        raw = '{"request_id":"one","operation":"context","operation":"answer","arguments":{}}\n'
        r = self.command('serve', '--agent', 'main', input=raw)
        self.assertEqual(json.loads(r.stdout)['error'], 'duplicate_json_key')

    def test_oversize_line_rejected_and_next_line_processed(self):
        raw = 'x' * 2000001 + '\n' + '{"request_id":"next","operation":"context","arguments":{}}\n'
        r = self.command('serve', '--agent', 'main', input=raw)
        lines = [json.loads(x) for x in r.stdout.splitlines()]
        self.assertEqual(lines[0]['error'], 'request_too_large')
        self.assertTrue(lines[1]['ok'])

    def test_existing_state_is_not_overwritten(self):
        key = (self.state / 'admin.key').read_bytes()
        r = self.command('init', '--config', str(ROOT / 'examples/local_task.json'))
        self.assertEqual(r.returncode, 2)
        self.assertEqual((self.state / 'admin.key').read_bytes(), key)

    def test_private_key_permissions_enforced(self):
        if os.name != 'posix': self.skipTest('POSIX permissions')
        (self.state / 'admin.key').chmod(0o644)
        r = self.command('audit')
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, '')

    def test_audit_and_incident_commands(self):
        self.command('serve', '--agent', 'main', input='{"request_id":"one","operation":"unsupported","arguments":{}}\n')
        audit = self.command('audit')
        self.assertTrue(json.loads(audit.stdout)['verified'])
        incidents = self.command('incidents', '--task', 'lakes-demo')
        rows = json.loads(incidents.stdout)['incidents']
        self.assertEqual(len(rows), 1)
        report = self.command('report', '--incident', rows[0]['id'])
        self.assertFalse(json.loads(report.stdout)['publication_authorized'])

    def test_suspension_persists_across_processes(self):
        r = self.command('suspend', '--task', 'lakes-demo', '--operator', 'admin')
        self.assertEqual(r.returncode, 0)
        r = self.command('serve', '--agent', 'main', input='{"request_id":"one","operation":"context","arguments":{}}\n')
        self.assertTrue(json.loads(r.stdout)['result']['snapshot']['control']['suspended'])
        self.assertEqual(self.command('resume', '--task', 'lakes-demo', '--operator', 'admin').returncode, 0)

    def test_agent_path_traversal_rejected(self):
        r = self.command('serve', '--agent', '../admin', input='')
        self.assertEqual(r.returncode, 2)
