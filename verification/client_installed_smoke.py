#!/usr/bin/env python3
"""Non-root, installed-application IPC and exact-checkpoint recovery; synthetic only.

Run the installed interpreter with -I from outside the source tree. This is not
native SDK or live-model qualification. No external network requests are made.
"""
from __future__ import annotations
import asyncio
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from agent_effect_gate import Broker, __version__
from agent_effect_gate.client import GateClient, UnixTransport
from agent_effect_gate.ipc import UnixGateServer
from agent_effect_gate.models import RunCheckpoint, run_client
from agent_effect_gate.tool_types import ToolResult

class FixtureTool:
    def __init__(self):
        self.calls = 0
    def manifest(self):
        return {'adapter': 'installed-capability-fixture-v1', 'effect': 'local_code'}
    def prepare(self, arguments, artifact):
        if arguments != {'value': 42}:
            raise ValueError('Unexpected fixture arguments')
        return dict(arguments)
    def invoke(self, plan, call_id):
        self.calls += 1
        return ToolResult({'value': plan['value']}, '42')

class FixtureModel:
    def __init__(self):
        self.index = 0
        self.calls = 0
    def export_state(self):
        return {'index': self.index}
    def import_state(self, value):
        self.index = value['index']
    def propose(self, context, last):
        self.calls += 1
        i = self.index
        self.index += 1
        if i == 0:
            return {'request_id': 'prepare', 'operation': 'propose_tool',
                    'arguments': {'tool_id': 'compute', 'arguments': {'value': 42}}}
        if i == 1:
            return {'request_id': 'execute-once', 'operation': 'execute_tool',
                    'arguments': {'call_id': last['result']['call_id']}}
        return {'request_id': 'final', 'operation': 'submit_answer',
                'arguments': {'text': 'Synthetic installed result: 42.', 'citations': [],
                              'limitations': ['No live provider used.']}}

def main():
    if os.geteuid() == 0:
        raise SystemExit('Run as a dedicated non-root service account.')
    with tempfile.TemporaryDirectory(prefix='aeg-capability-installed-') as temporary:
        root = Path(temporary)
        tool = FixtureTool()
        broker = Broker(root/'state.sqlite', secrets.token_bytes(32), tools={'compute': tool})
        token = broker.create_task('installed', 'synthetic', {'agents': ['main'], 'answer_mode': 'model',
            'tool_grants': {'compute': {'approval': 'required', 'max_calls': 4}}})['main']
        token_path = root/'main.token'
        token_path.write_text(token); token_path.chmod(0o600)
        server = UnixGateServer(root/'broker.sock', broker).start()
        try:
            client = GateClient(UnixTransport(root/'broker.sock', token, expected_server_uid=os.geteuid()))
            assert asyncio.run(client.arequest('context', {}, request_id='async-context'))['ok']
            checkpoint = RunCheckpoint(root/'run.json')
            first = FixtureModel()
            paused = run_client(first, client, checkpoint=checkpoint)
            assert paused['status'] == 'awaiting_approval' and tool.calls == 0
            pending = checkpoint.load()['pending_request']
            assert pending['request_id'] == 'execute-once'
            # Only the synthetic trusted fixture invokes broker control methods.
            broker.approve_tool(pending['arguments']['call_id'], reviewer='fixture-operator')
            resumed = FixtureModel()
            finished = run_client(resumed, client, checkpoint=checkpoint, resume=True)
            assert finished['result']['answer']['status'] == 'submitted'
            assert resumed.calls == 1 and tool.calls == 1 and checkpoint.load()['complete']
            again = FixtureModel()
            assert run_client(again, client, checkpoint=checkpoint, resume=True)['ok']
            assert again.calls == 0 and tool.calls == 1
            assert not client.request('approve_tool', {}, request_id='not-a-control-plane')['ok']
            budgets = client.view('context')['result']['snapshot']['control']['budgets']
            assert set(budgets) == {'actions', 'reads', 'retries'} and budgets['reads']['used'] > 0
            wire = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25',
                    'capabilities': {}, 'clientInfo': {'name': 'installed-test', 'version': '1'}}},
                {'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': {}},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}}]
            result = subprocess.run([sys.executable, '-I', '-m', 'agent_effect_gate.integrations.mcp',
                '--socket', str(root/'broker.sock'), '--token-file', str(token_path),
                '--broker-uid', str(os.geteuid())], input=''.join(json.dumps(x)+'\n' for x in wire),
                text=True, capture_output=True, cwd=root, timeout=15)
            assert result.returncode == 0, result.stderr
            messages = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(messages) == 2 and len(messages[-1]['result']['tools']) == 15
            assert all('error' not in message for message in messages)
            head = broker.store.verify()
        finally:
            server.stop(); broker.close()
        assert not (root/'broker.sock').exists()
        print(json.dumps({'passed': True, 'package_version': __version__, 'non_root': True,
            'installed_location': __import__('agent_effect_gate').__file__,
            'checks': ['real_Unix_transport', 'async_client', 'approval_pause', 'same_id_resume',
                       'single_tool_dispatch', 'completed_checkpoint_replay', 'no_admin_over_IPC',
                       'metered_client_snapshots', 'three_quota_dimensions', 'built_in_MCP_subprocess',
                       '15_capability_MCP_tools', 'verified_audit', 'clean_socket_shutdown'],
            'tool_dispatches': tool.calls, 'external_requests': 0, 'live_model_used': False}, indent=2))

if __name__ == '__main__':
    main()
