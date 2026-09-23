#!/usr/bin/env python3
"""Real loopback HTTP, exact approved POST, and model-authored answer protocol.

This is a scripted model driver over synthetic data, not a live LLM evaluation.
The separate operator approval below is explicit demonstration code, not an
approval action available to the model. Optional Linux code execution is real.
"""
from __future__ import annotations
import argparse
import base64
import json
import secrets
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_effect_gate import Broker
from agent_effect_gate.http_tools import HTTPTransport, HTTPRead, HTTPUpload
from agent_effect_gate.sandbox import LinuxSandbox


def demo(rootfs: str | None = None) -> dict:
    hits = []
    class Endpoint(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            hits.append({'method': 'GET', 'target': self.path})
            payload = json.dumps({'synthetic_units': [6, 9, 12], 'notice': 'Synthetic demo fixture, not business data.'}).encode()
            self.send_response(200); self.send_header('Content-Length', str(len(payload)))
            self.end_headers(); self.wfile.write(payload)
        def do_POST(self):
            payload = self.rfile.read(int(self.headers['Content-Length']))
            hits.append({'method': 'POST', 'target': self.path, 'bytes': len(payload),
                         'idempotency_key': self.headers.get('Idempotency-Key')})
            reply = b'{"received":true}'
            self.send_response(201); self.send_header('Content-Length', str(len(reply)))
            self.end_headers(); self.wfile.write(reply)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        with tempfile.TemporaryDirectory() as folder:
            transport = HTTPTransport(f'http://127.0.0.1:{server.server_port}', allow_loopback=True)
            tools = {'research': HTTPRead(transport, '/data', ()), 'upload': HTTPUpload(transport, '/upload')}
            grants = {'research': {'approval': 'standing', 'allow_argument_egress': True, 'max_calls': 5},
                      'upload': {'approval': 'required', 'max_calls': 1}}
            if rootfs:
                tools['code'] = LinuxSandbox(rootfs)
                grants['code'] = {'approval': 'standing', 'max_calls': 2}
            broker = Broker(Path(folder) / 'state.sqlite', secrets.token_bytes(32), tools=tools)
            try:
                token = broker.create_task('demo', 'demo', {'agents': ['main'], 'local_only': False,
                                                           'tool_grants': grants})['main']
                def call(operation, arguments=None, request_id=None):
                    return broker.handle(token, {'request_id': request_id or secrets.token_hex(8),
                                                  'operation': operation, 'arguments': arguments or {}})
                initial = call('answer')['result']['answer']
                assert initial['status'] == 'awaiting_model_answer' and initial['text'] is None
                proposal = call('propose_tool', {'tool_id': 'research', 'arguments': {'path': '/data/current', 'query': {}}})
                observation = call('execute_tool', {'call_id': proposal['result']['call_id']})['result']['observation']
                data = json.loads(observation['text']); total = sum(data['synthetic_units'])
                prose = f"The synthetic fixture contains {len(data['synthetic_units'])} values totaling {total} units."
                code_result = None
                if rootfs:
                    code = "import json\nprint(sum(json.loads(" + repr(json.dumps(data)) + ")[\"synthetic_units\"]))\n"
                    cp = call('propose_tool', {'tool_id': 'code', 'arguments': {'language': 'python', 'code': code, 'inputs': {}, 'outputs': []}})
                    code_result = call('execute_tool', {'call_id': cp['result']['call_id']})['result']
                    assert code_result['state'] == 'SUCCEEDED', code_result
                    assert code_result['observation']['data']['stdout'].strip() == str(total)
                art = call('put_artifact', {'media_type': 'text/plain', 'data_b64': base64.b64encode(prose.encode()).decode()})['result']['artifact_id']
                upload = call('propose_tool', {'tool_id': 'upload', 'arguments': {'artifact_id': art}})['result']['call_id']
                args = {'call_id': upload}
                waiting = call('execute_tool', args, 'send-once')
                assert waiting['error'] == 'approval_required'
                assert len(hits) == 1  # GET happened; no POST yet.
                # TRUSTED operator path: inspect exact bytes and grant that one effect.
                review = broker.review_tool(upload)
                assert base64.b64decode(review['prepared_request']['payload_b64']).decode() == prose
                broker.approve_tool(upload, reviewer='demo-operator')
                sent = call('execute_tool', args, 'send-once')
                replay = call('execute_tool', args, 'send-once')
                assert sent['result']['state'] == replay['result']['state'] == 'SUCCEEDED'
                assert len(hits) == 2  # Same request ID, exactly one POST.
                final = call('submit_answer', {'text': prose, 'citations': [{'observation_id': observation['observation_id'],
                                             'quote': observation['text']}],
                                              'limitations': ['Synthetic data; scripted driver, not a live model.']})['result']['answer']
                return {'driver': 'scripted model adapter; real HTTP and optional Linux sandbox',
                        'answer_before_model_submission': initial['status'], 'network_requests': hits,
                        'same_request_id_after_approval': sent['result']['state'],
                        'code_state': code_result['state'] if code_result else 'not_requested',
                        'final_answer': final, 'audit_head': broker.store.verify()}
            finally:
                broker.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', help='Absolute operator-built clean Linux rootfs')
    args = parser.parse_args()
    print(json.dumps(demo(args.rootfs), indent=2))
