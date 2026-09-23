#!/usr/bin/env python3
"""Separate broker process + real HTTP read and approved upload, without an LLM key.

The driver is scripted over synthetic data. The approval is a separate explicit
operator command, not a tool exposed to any model. This tests our framework-neutral
surface; native SDK runtime tests live in integration_tests/.
"""
from __future__ import annotations
import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_effect_gate.cli import initialize
from agent_effect_gate.client import GateClient
from agent_effect_gate.integrations.common import GateToolkit
from agent_effect_gate.ipc import TransportError


def demo() -> dict:
    hits = []
    class Endpoint(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            hits.append({'method':'GET','path':self.path})
            body = b'{"synthetic_units":[6,9,12],"source":"local synthetic fixture"}'
            self.send_response(200); self.send_header('Content-Length',str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            hits.append({'method':'POST','path':self.path,'bytes':len(body),
                         'idempotency_key':self.headers.get('Idempotency-Key')})
            response = b'{"accepted":true}'
            self.send_response(201); self.send_header('Content-Length',str(len(response)))
            self.end_headers(); self.wfile.write(response)
    http = ThreadingHTTPServer(('127.0.0.1',0), Endpoint)
    thread = threading.Thread(target=http.serve_forever,daemon=True); thread.start()
    try:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            state = directory/'state'; path = directory/'gate.sock'
            origin = f'http://127.0.0.1:{http.server_port}'
            config = {'task_id':'sdk-demo','tenant_id':'synthetic','sources':[],
                      'policy':{'agents':['main'],'answer_mode':'model','local_only':False,
                                'tool_grants':{'research':{'approval':'standing','allow_argument_egress':True,'max_calls':3},
                                               'upload':{'approval':'required','max_calls':1}}},
                      'tools':[{'id':'research','kind':'http_read','origin':origin,'path_prefix':'/fixture','query_keys':[],
                                'allow_loopback':True},
                               {'id':'upload','kind':'http_upload','origin':origin,'path':'/upload','allow_loopback':True}]}
            config_path = directory/'task.json'; config_path.write_text(json.dumps(config))
            reviewer_password = "synthetic-reviewer-password-0001"
            password_path = directory / "reviewer.password"
            password_path.write_text(reviewer_password); password_path.chmod(0o600)
            initialize(state, config_path, reviewer=("demo-reviewer", reviewer_password))
            # For a production deployment, provision this copy into a DIFFERENT UID's
            # private directory. Same-UID processes here are a functional demonstration.
            token_path = directory/'framework.token'
            token_path.write_bytes((state/'sessions/main.token').read_bytes()); token_path.chmod(0o600)
            env = {**os.environ,'PYTHONPATH':str(ROOT)}
            process = subprocess.Popen([sys.executable,'-m','agent_effect_gate','serve-unix','--state',str(state),
                '--socket',str(path),'--allow-uid',str(os.geteuid())],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
            try:
                client = GateClient.unix(path, token_path, expected_server_uid=os.geteuid(),timeout=10)
                deadline = time.monotonic()+15
                while not path.exists():
                    if process.poll() is not None: raise RuntimeError('Broker did not start')
                    if time.monotonic()>deadline: raise RuntimeError('Broker startup timeout')
                    time.sleep(.02)
                toolkit = GateToolkit(client)
                def decode(raw):
                    result=json.loads(raw)
                    if not result['ok']: raise AssertionError(result)
                    return result['result']
                before = decode(toolkit.aeg_answer('before'))['answer']
                result = decode(toolkit.aeg_call_tool('research','{"path":"/fixture/data","query":{}}','research-1'))
                assert result['state']=='SUCCEEDED'
                observation = result['observation']
                data = json.loads(observation['text'])
                prose = f"The synthetic values total {sum(data['synthetic_units'])} units."
                artifact = decode(toolkit.aeg_put_artifact('text/plain',base64.b64encode(prose.encode()).decode(),'artifact-1'))
                args = json.dumps({'artifact_id':artifact['artifact_id']})
                pending = json.loads(toolkit.aeg_call_tool('upload',args,'send-1'))
                assert pending['error']=='approval_required'
                assert [h['method'] for h in hits]==['GET']
                def operator(command, *options):
                    out=subprocess.run([sys.executable,'-m','agent_effect_gate',command,'--state',str(state),
                        '--call',pending['call_id'],*options],capture_output=True,check=True,text=True,timeout=15,env=env)
                    return json.loads(out.stdout)
                reviewed = operator('review-tool')
                assert base64.b64decode(reviewed['prepared_request']['payload_b64']).decode()==prose
                operator('approve-tool', '--reviewer', 'demo-reviewer', '--password-file', str(password_path))
                sent = decode(toolkit.aeg_call_tool('upload',args,'send-1'))
                replay = decode(toolkit.aeg_call_tool('upload',args,'send-1'))
                assert sent['state']==replay['state']=='SUCCEEDED'
                assert [h['method'] for h in hits]==['GET','POST']
                decode(toolkit.aeg_submit_answer(prose,json.dumps([{'observation_id':observation['observation_id'],
                    'quote':observation['text']}]),'["Synthetic data and scripted driver; no live model was called."]','submit-1'))
                final = decode(toolkit.aeg_answer('final'))['answer']
                return {'driver':'scripted; no native SDK or live model used','separate_broker_process':True,
                        'same_os_uid_for_local_demo':True,'initial_status':before['status'],
                        'network_requests':hits,'same_id_approval_retry':sent['state'],
                        'dispatch_count':len([h for h in hits if h['method']=='POST']), 'final_answer':final}
            finally:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
    finally:
        http.shutdown(); http.server_close(); thread.join(2)

if __name__=='__main__': print(json.dumps(demo(),indent=2))
