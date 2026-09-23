#!/usr/bin/env python3
"""Run with the installed wheel's interpreter using -I, outside the source tree.

No network, customer data, or model credentials are used. Run as a non-root UID.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from agent_effect_gate import __version__


def main():
    if os.geteuid() == 0:
        raise SystemExit('Run the deployment smoke test as a dedicated non-root user.')
    with tempfile.TemporaryDirectory(prefix='aeg-installed-') as temp:
        root = Path(temp)
        state, backup, restored = root / 'state', root / 'backup', root / 'restored'
        config, anchor = root / 'config.json', root / 'anchor.json'
        config.write_text(json.dumps({'task_id': 'smoke-task', 'tenant_id': 'smoke-tenant', 'sources': [], 'tools': [],
            'policy': {'agents': ['main'], 'local_only': True, 'stage': 'deployment', 'answer_mode': 'model'}}))
        def command(*args, raw=None, expected=0):
            result = subprocess.run([sys.executable, '-I', '-m', 'agent_effect_gate', *map(str, args)],
                input=raw, capture_output=True, text=True, cwd=root, timeout=20)
            if result.returncode != expected:
                raise RuntimeError('Smoke command failed: ' + args[0] + ': ' + result.stderr)
            return json.loads(result.stdout)
        command('validate-config', '--config', config, '--production')
        initialized = command('init', '--state', state, '--config', config, '--production')
        anchor.write_text(json.dumps(initialized['audit_head']))
        ready = command('doctor', '--state', state, '--anchor', anchor, '--production')
        assert ready['ready']
        actions = [
            {'request_id': 'list-1', 'operation': 'list_tools', 'arguments': {}},
            {'request_id': 'answer-1', 'operation': 'submit_answer', 'arguments': {
                'text': 'Synthetic installed-application smoke result.', 'citations': [], 'limitations': ['No live model or network used.']}}
        ]
        result = subprocess.run([sys.executable, '-I', '-m', 'agent_effect_gate', 'serve', '--state', str(state),
            '--agent', 'main', '--anchor', str(anchor), '--production'],
            input=''.join(json.dumps(a) + '\n' for a in actions), text=True, capture_output=True, cwd=root, timeout=20)
        assert result.returncode == 0, result.stderr
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(responses) == 2 and all(r['ok'] for r in responses)
        assert responses[-1]['result']['answer']['status'] == 'submitted'
        audited = command('audit', '--state', state, '--anchor', anchor)
        anchor.write_text(json.dumps(audited))  # Also exercises command-envelope anchors.
        saved = command('backup', '--state', state, '--destination', backup, '--anchor', anchor)
        recovered = command('restore', '--backup', backup, '--state', restored, '--anchor', anchor, '--operator', 'smoke-operator')
        assert saved['backed_up'] and recovered['all_tasks_suspended']
        stopped = command('doctor', '--state', restored, '--anchor', anchor, '--production', expected=2)
        assert not stopped['ready']
        print(json.dumps({'passed': True, 'package_version': __version__, 'non_root': True,
            'installed_location': __import__('agent_effect_gate').__file__,
            'checks': ['config', 'atomic_init', 'production_doctor', 'jsonl_tools', 'model_answer', 'external_anchor',
                       'backup', 'guarded_restore', 'restored_state_not_ready'],
            'external_requests': 0}, indent=2))


if __name__ == '__main__':
    main()
