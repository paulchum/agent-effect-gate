#!/usr/bin/env python3
"""Non-root installed-application customer setup, real code execution and MCP workflow.

No external requests or model credentials. Requires a qualified clean Linux rootfs.
Run: /installed/venv/bin/python -I verification/customer_installed_smoke.py --rootfs /trusted/rootfs
"""
from __future__ import annotations
import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from agent_effect_gate import __version__
from agent_effect_gate.cli import _broker
from agent_effect_gate.reviewer_auth import ReviewerAuth


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--rootfs', required=True, type=Path); args = parser.parse_args()
    if os.geteuid() == 0: raise SystemExit('Run under the dedicated non-root service UID.')
    with tempfile.TemporaryDirectory(prefix='aeg-customer-installed-') as temporary:
        root = Path(temporary); state = root / 'state'; password_file = root / 'review-password'; anchor = root / 'anchor.json'
        password = secrets.token_urlsafe(32); password_file.write_text(password + '\n'); password_file.chmod(0o600)
        def command(*words, expected=0):
            response = subprocess.run([sys.executable, '-I', '-m', 'agent_effect_gate', *map(str, words)], capture_output=True,
                                      text=True, cwd=root, timeout=45)
            assert response.returncode == expected, (words[0], response.stderr)
            return json.loads(response.stdout)
        initialized = command('setup', '--state', state, '--rootfs', args.rootfs, '--reviewer', 'acceptance-reviewer', '--password-file', password_file)
        assert initialized['profile'] == 'customer' and initialized['code_approval'] == 'standing'
        anchor.write_text(json.dumps(initialized['audit_head'])); anchor.chmod(0o600)
        assert command('doctor', '--state', state, '--anchor', anchor, '--production', '--check-sandbox')['ready']
        broker = _broker(state)
        try:
            auth = ReviewerAuth(broker.store); token, reviewer = auth.login('acceptance-reviewer', password)
            assert reviewer.tasks == ('customer-task',); auth.logout(reviewer)
        finally: broker.close()
        process = subprocess.Popen([sys.executable, '-I', '-m', 'agent_effect_gate', 'mcp', '--state', str(state), '--agent', 'main',
                                    '--anchor', str(anchor), '--production', '--check-sandbox'], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root)
        try:
            wire_id = 0
            def rpc(method, params=None, notification=False):
                nonlocal wire_id
                wire_id += 1; message = {'jsonrpc': '2.0', 'method': method, 'params': params or {}}
                if not notification: message['id'] = wire_id
                process.stdin.write(json.dumps(message) + '\n'); process.stdin.flush()
                if not notification:
                    reply = json.loads(process.stdout.readline()); assert 'error' not in reply, reply
                    return reply['result']
            def call(operation, args=None):
                value = rpc('tools/call', {'name': 'aeg_' + operation, 'arguments': args or {}})
                assert not value['isError'], value
                return value['structuredContent']['result']
            negotiated = rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'installed-acceptance', 'version': '1'}})
            rpc('notifications/initialized', notification=True)
            assert len(rpc('tools/list')['tools']) == 15
            discovered = call('list_tools')
            assert 'python_docs' in json.dumps(discovered) and 'compute' in json.dumps(discovered)
            prepared = call('propose_tool', {'tool_id': 'compute', 'arguments': {'language': 'python',
                'code': 'print(sum(i*i for i in range(1, 11)))', 'inputs': {}, 'outputs': []}})
            executed = call('execute_tool', {'call_id': prepared['call_id'], 'request_id': 'compute-once'})
            assert executed['state'] == 'SUCCEEDED', executed
            observation = executed['observation']; assert observation['text'].strip() == '385'
            # The same stable id never executes the code twice.
            replay = call('execute_tool', {'call_id': prepared['call_id'], 'request_id': 'compute-once'})
            assert replay['observation']['observation_id'] == observation['observation_id']
            final = call('submit_answer', {'text': 'The sum of the squares of integers 1 through 10 is 385.',
                'citations': [{'observation_id': observation['observation_id'], 'quote': '385'}],
                'limitations': ['Synthetic isolated computation; no live model or external service.']})
            assert final['answer']['status'] == 'submitted'
            process.stdin.close(); process.stdin = None; _, error = process.communicate(timeout=15); assert process.returncode == 0, error
        finally:
            if process.poll() is None: process.kill(); process.wait()
        print(json.dumps({'passed': True, 'package_version': __version__, 'non_root': True,
            'installed_location': __import__('agent_effect_gate').__file__, 'protocol_version': negotiated['protocolVersion'],
            'checks': ['customer_setup', 'real_sandbox_preflight', 'reviewer_login', 'production_doctor', 'stdio_MCP',
                       '15_agent_tools', 'network_adapter_enabled', 'real_isolated_Python', 'idempotent_execution', 'cited_final_answer'],
            'isolated_calculation': 385, 'external_requests': 0, 'live_model_used': False}, indent=2))


if __name__ == '__main__': main()
