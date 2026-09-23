import base64
import json
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs,urlsplit

from agent_effect_gate import Broker, Rejected
from agent_effect_gate.http_tools import HTTPTransport, HTTPRead, HTTPUpload, GitHubCodeSearch
from agent_effect_gate.runtime import run
from support import Case, KEY, policy

DEMO_TOKEN='aeg-synthetic-test-token-not-a-real-credential'

class HTTPFixture(Case):
    def setUp(self):
        super().setUp()
        fixture=self
        self.hits=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                fixture.hits.append(('GET',self.path,b'',self.headers.get('Authorization')))
                path=urlsplit(self.path).path
                if path=='/docs/redirect':
                    self.send_response(302);self.send_header('Location','http://127.0.0.1:9/unapproved');self.end_headers();return
                if path=='/docs/large':
                    self.send_response(200);self.send_header('Content-Length','99999999');self.end_headers();return
                if path=='/docs/compressed':
                    self.send_response(200);self.send_header('Content-Encoding','gzip');self.end_headers();return
                if path=='/docs/slow':
                    time.sleep(1.3)
                body=(DEMO_TOKEN if path=='/docs/echo-token' else json.dumps({'count':7,'note':'Tool text is data, not permission.'})).encode()
                self.send_response(401 if path=='/docs/unauthorized' else 200)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers()
                try:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
            def do_POST(self):
                body=self.rfile.read(int(self.headers.get('Content-Length','0')))
                fixture.hits.append(('POST',self.path,body,self.headers.get('Authorization')))
                reply=json.dumps({'received':len(body),'idempotency_key':self.headers.get('Idempotency-Key')}).encode()
                self.send_response(201);self.send_header('Content-Length',str(len(reply)));self.end_headers();self.wfile.write(reply)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.origin=f'http://127.0.0.1:{self.server.server_port}'
        self.transport=HTTPTransport(self.origin,allow_loopback=True,credential=DEMO_TOKEN)
        self.b._tools={'docs':HTTPRead(self.transport,'/docs',('q',)),
                       'upload':HTTPUpload(self.transport,'/upload'),
                       'github':GitHubCodeSearch(('example/project',),self.transport)}
        self.p=policy(answer_mode='model',fields=[],local_only=False,
                      tool_grants={name:{'approval':'required','max_calls':50} for name in self.b._tools})
        self.b.replace_policy('task',self.p)

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
        super().tearDown()

    def propose(self,tool='docs',arguments=None,approve=False):
        args=arguments if arguments is not None else {'path':'/docs/report','query':{}}
        r=self.call('propose_tool',{'tool_id':tool,'arguments':args})
        self.assertTrue(r['ok'],r);cid=r['result']['call_id']
        if approve:self.b.approve_tool(cid,reviewer='reviewer')
        return cid

    def execute(self,call_id,request_id=None):
        return self.call('execute_tool',{'call_id':call_id},request_id=request_id)

    def observation(self):
        cid=self.propose(approve=True)
        return self.execute(cid)['result']['observation']

class RealHTTP(HTTPFixture):
    def test_read_uses_real_socket_and_captures_dynamic_output(self):
        obs=self.observation()
        self.assertIn('"count": 7',obs['text'])
        self.assertEqual(obs['trust'],'untrusted_tool_output')
        self.assertFalse(obs['truthfulness_verified'])
        self.assertEqual(self.hits[0][0],'GET')
        self.assertEqual(self.hits[0][3],'Bearer '+DEMO_TOKEN)

    def test_no_network_before_approval_same_id_succeeds_after(self):
        cid=self.propose()
        self.assertEqual(self.execute(cid,'same')['error'],'approval_required');self.assertEqual(self.hits,[])
        self.b.approve_tool(cid,reviewer='reviewer')
        self.assertEqual(self.execute(cid,'same')['result']['state'],'SUCCEEDED')
        self.assertEqual(self.execute(cid,'same')['result']['state'],'SUCCEEDED');self.assertEqual(len(self.hits),1)

    def test_exact_upload_body_and_no_duplicate_side_effect(self):
        payload=b'private task artifact\x00\x01'
        aid=self.artifact(payload)
        cid=self.propose('upload',{'artifact_id':aid})
        review=self.b.review_tool(cid)
        self.assertEqual(base64.b64decode(review['prepared_request']['payload_b64']),payload)
        self.assertFalse(self.execute(cid,'send')['ok']);self.assertEqual(self.hits,[])
        self.b.approve_tool(cid,reviewer='reviewer')
        r=self.execute(cid,'send');self.assertEqual(r['result']['state'],'SUCCEEDED')
        for _ in range(5):self.execute(cid,'send')
        self.assertEqual(len(self.hits),1);self.assertEqual(self.hits[0][:3],('POST','/upload',payload))
        self.assertEqual(json.loads(r['result']['observation']['text'])['idempotency_key'],cid)

    def test_redirect_does_not_follow_or_forward_credential(self):
        cid=self.propose(arguments={'path':'/docs/redirect','query':{}},approve=True)
        r=self.execute(cid)['result']
        self.assertEqual(r['state'],'FAILED');self.assertEqual(r['observation']['data']['error'],'redirect_refused')
        self.assertEqual(len(self.hits),1)

    def test_oversized_and_encoded_responses_fail_closed(self):
        for path in ['/docs/large','/docs/compressed']:
            cid=self.propose(arguments={'path':path,'query':{}},approve=True)
            self.assertEqual(self.execute(cid)['result']['state'],'FAILED')

    def test_unauthorized_response_is_failure_not_invented_data(self):
        cid=self.propose(arguments={'path':'/docs/unauthorized','query':{}},approve=True)
        r=self.execute(cid)['result'];self.assertEqual(r['state'],'FAILED')
        self.assertEqual(r['observation']['data']['http_status'],401)
        self.assertTrue(any(n['code']=='tool_failed' for n in self.answer()['notices']))

    def test_tool_exceptions_do_not_leak_details_or_retry(self):
        cid=self.propose(approve=True)
        # A failed GET is terminal, sanitized, and never automatically retried.
        self.b._tools['docs']=HTTPRead(HTTPTransport(self.origin,allow_loopback=True,timeout_seconds=1),'/docs',('q',))
        cid=self.propose(arguments={'path':'/docs/slow','query':{}},approve=True)
        r=self.execute(cid,'timeout')['result'];self.assertEqual(r['state'],'FAILED')
        self.assertEqual(self.execute(cid,'timeout')['result']['state'],'FAILED')
        self.assertEqual(len(self.hits),1)

    def test_model_cannot_set_host_headers_credentials_or_method(self):
        for extra in [{'headers':{'Authorization':'leaked'}},{'origin':'https://unapproved.example'}, {'method':'POST'}, {'credential':'leaked'}]:
            r=self.call('propose_tool',{'tool_id':'docs','arguments':{'path':'/docs/report','query':{},**extra}})
            self.assertFalse(r['ok'])
        self.assertEqual(self.hits,[])

    def test_path_traversal_and_query_keys_rejected_before_network(self):
        for path in ['/elsewhere','//unapproved.example','/docs/../private','/docs/%2e%2e/private','/docs\\private','/docs-evasion']:
            r=self.call('propose_tool',{'tool_id':'docs','arguments':{'path':path,'query':{}}});self.assertFalse(r['ok'],path)
        r=self.call('propose_tool',{'tool_id':'docs','arguments':{'path':'/docs/report','query':{'token':'secret'}}})
        self.assertEqual(r['error'],'query_not_allowed');self.assertEqual(self.hits,[])

    def test_standing_read_requires_explicit_argument_egress(self):
        self.p['tool_grants']['docs']['approval']='standing';self.b.replace_policy('task',self.p)
        r=self.call('propose_tool',{'tool_id':'docs','arguments':{'path':'/docs/report','query':{}}})
        self.assertEqual(r['error'],'argument_egress_not_authorized')
        self.p['tool_grants']['docs']['allow_argument_egress']=True;self.b.replace_policy('task',self.p)
        cid=self.propose();self.assertEqual(self.execute(cid)['result']['state'],'SUCCEEDED')

    def test_standing_upload_is_not_allowed(self):
        self.p['tool_grants']['upload']['approval']='standing';self.b.replace_policy('task',self.p)
        r=self.call('propose_tool',{'tool_id':'upload','arguments':{'artifact_id':self.artifact()}})
        self.assertEqual(r['error'],'writes_require_exact_approval')

    def test_registered_credential_is_redacted_if_reflected(self):
        cid=self.propose(arguments={'path':'/docs/echo-token','query':{}},approve=True)
        obs=self.execute(cid)['result']['observation'];self.assertNotIn(DEMO_TOKEN,str(obs))
        audit=str([dict(x) for x in self.b.store.db.execute('SELECT * FROM audit')])
        self.assertNotIn(DEMO_TOKEN,audit);self.assertNotIn(DEMO_TOKEN,str(self.b.review_tool(cid)))

    def test_github_search_scope_is_fixed_not_an_arbitrary_query(self):
        cid=self.propose('github',{'repository':'example/project','terms':['parser','test_case'],'per_page':10},approve=True)
        self.assertEqual(self.execute(cid)['result']['state'],'SUCCEEDED')
        parsed=urlsplit(self.hits[0][1]);self.assertEqual(parsed.path,'/search/code')
        self.assertEqual(parse_qs(parsed.query)['q'],['repo:example/project "parser" "test_case"'])
        for repo,terms in [('elsewhere/private',['parser']),('example/project',['repo:other/repo']),('example/project',['" OR x'])]:
            r=self.call('propose_tool',{'tool_id':'github','arguments':{'repository':repo,'terms':terms,'per_page':10}})
            self.assertFalse(r['ok'])
        self.assertEqual(len(self.hits),1)

    def test_nonpublic_dns_answers_are_rejected(self):
        t=HTTPTransport('https://example.test')
        for address in ['127.0.0.1','10.0.0.1','169.254.169.254','::1']:
            with patch('agent_effect_gate.http_tools.resolve_addresses',return_value=[address]):
                with self.assertRaises(OSError):t._addresses()

    def test_plain_http_requires_explicit_literal_loopback(self):
        for origin,allow in [('http://example.test',False),('http://localhost',True),('https://example.test',True),('http://127.0.0.1',False)]:
            with self.assertRaises(ValueError):HTTPTransport(origin,allow_loopback=allow)

class ToolAuthorization(HTTPFixture):
    def test_manifest_or_policy_change_invalidates_approval(self):
        cid=self.propose(approve=True)
        self.b._tools['docs']=HTTPRead(self.transport,'/',('q',))
        self.assertEqual(self.execute(cid)['error'],'approval_binding_changed');self.assertEqual(self.hits,[])
        cid=self.propose(approve=True);self.b.replace_policy('task',self.p)
        self.assertEqual(self.execute(cid)['error'],'approval_binding_changed');self.assertEqual(self.hits,[])

    def test_credential_rotation_invalidates_pending_approval(self):
        cid=self.propose(approve=True)
        self.b._tools['docs']=HTTPRead(HTTPTransport(self.origin,allow_loopback=True,credential=DEMO_TOKEN+'new'),'/docs',('q',))
        self.assertEqual(self.execute(cid)['error'],'approval_binding_changed');self.assertEqual(self.hits,[])

    def test_approval_expiry_revocation_and_suspension(self):
        cid=self.propose(approve=True);self.clock.advance(301)
        self.assertEqual(self.execute(cid)['error'],'approval_expired')
        cid=self.propose(approve=True);self.b.revoke_tool(cid,reviewer='reviewer')
        self.assertEqual(self.execute(cid)['result']['state'],'REVOKED')
        cid=self.propose(approve=True);self.b.set_suspended('task',True,operator='admin')
        self.assertEqual(self.execute(cid)['error'],'task_suspended');self.assertEqual(self.hits,[])

    def test_call_and_observation_scope_bound_to_task_and_agent(self):
        cid=self.propose(approve=True)
        self.assertEqual(self.call('execute_tool',{'call_id':cid},agent='worker')['error'],'tool_call_not_found')
        obs=self.execute(cid)['result']['observation']
        self.assertEqual(self.call('read_observation',{'observation_id':obs['observation_id']},agent='worker')['error'],'observation_not_found')
        other=self.b.create_task('other','tenant',self.p)
        self.assertEqual(self.call('read_observation',{'observation_id':obs['observation_id']},token=other['main'])['error'],'observation_not_found')

    def test_budget_checked_at_dispatch(self):
        self.p['tool_grants']['docs']['max_calls']=1;self.b.replace_policy('task',self.p)
        first=self.propose(approve=True);second=self.propose(approve=True)
        self.assertEqual(self.execute(first)['result']['state'],'SUCCEEDED')
        self.assertEqual(self.execute(second)['error'],'tool_budget_exhausted');self.assertEqual(len(self.hits),1)

    def test_concurrent_identical_execution_dispatches_once(self):
        cid=self.propose(approve=True)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results=list(pool.map(lambda _:self.execute(cid,'same'),range(6)))
        self.assertTrue(all(r['ok'] for r in results),results);self.assertEqual(len(self.hits),1)
        self.assertEqual(self.execute(cid,'same')['result']['state'],'SUCCEEDED')

    def test_separate_process_can_approve_and_existing_id_can_retry(self):
        cid=self.propose();self.execute(cid,'same')
        control=Broker(self.path,KEY,clock=self.clock)
        control.approve_tool(cid,reviewer='reviewer');control.close()
        self.assertEqual(self.execute(cid,'same')['result']['state'],'SUCCEEDED')

    def test_tampered_prepared_request_fails_closed(self):
        cid=self.propose(approve=True)
        self.b.store.db.execute("UPDATE tool_calls SET plan='{}' WHERE id=?",(cid,))
        self.assertEqual(self.execute(cid)['error'],'integrity_or_storage_failure');self.assertEqual(self.hits,[])

    def test_pre_dispatch_audit_failure_causes_no_http_request(self):
        cid=self.propose(approve=True);original=self.b.store.append
        def fail(db,task,agent,kind,details):
            if kind=='tool_dispatch_intent':raise sqlite3.OperationalError('failure')
            return original(db,task,agent,kind,details)
        self.b.store.append=fail
        self.assertEqual(self.execute(cid)['error'],'integrity_or_storage_failure');self.assertEqual(self.hits,[])
        self.b.store.append=original

    def test_post_dispatch_failure_does_not_retry_on_restart(self):
        cid=self.propose(approve=True);original=self.b.store.append
        def fail(db,task,agent,kind,details):
            if kind=='tool_result':raise sqlite3.OperationalError('failure')
            return original(db,task,agent,kind,details)
        self.b.store.append=fail
        self.assertEqual(self.execute(cid,'same')['error'],'post_dispatch_audit_unavailable');self.assertEqual(len(self.hits),1)
        self.b.store.append=original;tools=self.b._tools;self.b.close()
        self.b=Broker(self.path,KEY,clock=self.clock,tools=tools)
        self.assertEqual(self.execute(cid,'same')['result']['state'],'DISPATCHING');self.assertEqual(len(self.hits),1)

class ModelAnswers(HTTPFixture):
    def test_no_prebound_fields_and_no_automatic_answer(self):
        a=self.answer();self.assertEqual(a['status'],'awaiting_model_answer');self.assertIsNone(a['text'])
        r=self.call('submit_answer',{'text':'My own analysis, not an operator field.','citations':[],'limitations':['This is a model judgment.']})
        self.assertTrue(r['ok']);self.assertEqual(r['result']['answer']['text'],'My own analysis, not an operator field.')
        self.assertFalse(r['result']['answer']['truthfulness_verified'])

    def test_model_can_cite_actual_quote_from_dynamic_network_result(self):
        obs=self.observation()
        r=self.call('submit_answer',{'text':'The returned count is seven.','citations':[{'observation_id':obs['observation_id'],'quote':'"count": 7'}],'limitations':[]})
        self.assertTrue(r['ok'],r);self.assertEqual(r['result']['answer']['citations'][0]['sha256'],obs['sha256'])

    def test_invalid_citations_and_fake_quote_are_rejected(self):
        obs=self.observation()
        for c in [{'observation_id':'obs_missing','quote':'anything'}, {'observation_id':obs['observation_id'],'quote':'"count": 999'}]:
            r=self.call('submit_answer',{'text':'unsupported','citations':[c],'limitations':[]});self.assertFalse(r['ok'])
        self.assertIsNone(self.answer()['text'])

    def test_citations_are_not_misrepresented_as_semantic_truth_checks(self):
        obs=self.observation()
        r=self.call('submit_answer',{'text':'An unsupported model interpretation.','citations':[{'observation_id':obs['observation_id'],'quote':'"count": 7'}],'limitations':[]})
        self.assertTrue(r['ok']);self.assertFalse(r['result']['answer']['truthfulness_verified'])

    def test_model_cannot_hide_notices_or_restore_old_draft_on_retry(self):
        args={'text':'first','citations':[],'limitations':[]}
        self.call('submit_answer',args,request_id='draft-one')
        self.call('submit_answer',{**args,'text':'second'},request_id='draft-two')
        self.call('unsupported')
        r=self.call('submit_answer',args,request_id='draft-one')['result']['answer']
        self.assertEqual(r['text'],'second');self.assertTrue(r['notices'])
        self.assertFalse(self.call('submit_answer',{**args,'notices':[]})['ok'])

    def test_runtime_model_selects_tool_and_writes_answer(self):
        self.p['tool_grants']['docs'].update(approval='standing',allow_argument_egress=True);self.b.replace_policy('task',self.p)
        class Adapter:
            step=0
            def propose(inner,context,last):
                inner.step+=1
                if inner.step==1:op,args='propose_tool',{'tool_id':'docs','arguments':{'path':'/docs/report','query':{}}}
                elif inner.step==2:op,args='execute_tool',{'call_id':last['result']['call_id']}
                else:
                    obs=last['result']['observation'];count=json.loads(obs['text'])['count']
                    op,args='submit_answer',{'text':f'I read the endpoint; it returned {count}.','citations':[{'observation_id':obs['observation_id'],'quote':f'"count": {count}'}],'limitations':[]}
                return {'request_id':f'model-{inner.step}','operation':op,'arguments':args}
        r=run(Adapter(),self.b,self.tokens['main'])
        self.assertEqual(r['result']['answer']['text'],'I read the endpoint; it returned 7.')
        self.assertEqual(len(self.hits),1)

class RealTLS(HTTPFixture):
    def tls_server(self,san='IP:127.0.0.1'):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        cert=Path(directory.name)/'cert.pem';key=Path(directory.name)/'key.pem'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName='+san],
                       check=True,capture_output=True,timeout=10)
        self.server.shutdown();self.thread.join(timeout=2)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cert),str(key))
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        return f'https://127.0.0.1:{self.server.server_port}',str(cert)

    def test_real_tls_with_valid_trust_and_hostname(self):
        origin,cert=self.tls_server()
        self.b._tools['docs']=HTTPRead(HTTPTransport(origin,allow_loopback=True,ca_file=cert),'/docs')
        self.assertEqual(self.execute(self.propose(approve=True))['result']['state'],'SUCCEEDED')

    def test_untrusted_certificate_is_not_bypassed(self):
        origin,cert=self.tls_server()
        self.b._tools['docs']=HTTPRead(HTTPTransport(origin,allow_loopback=True),'/docs')
        self.assertEqual(self.execute(self.propose(approve=True))['result']['state'],'FAILED')
        self.assertEqual(self.hits,[])

    def test_trusted_certificate_still_requires_correct_hostname(self):
        origin,cert=self.tls_server('DNS:localhost')
        self.b._tools['docs']=HTTPRead(HTTPTransport(origin,allow_loopback=True,ca_file=cert),'/docs')
        self.assertEqual(self.execute(self.propose(approve=True))['result']['state'],'FAILED')
        self.assertEqual(self.hits,[])

class NetworkDeadlines(HTTPFixture):
    def test_dns_helper_has_a_hard_timeout_and_no_credential_environment(self):
        from agent_effect_gate.http_tools import resolve_addresses
        with patch('agent_effect_gate.http_tools.capture',return_value={'returncode':-9,'stop_reason':'timeout','stdout':b'','stderr':b''}) as cap:
            with self.assertRaises(OSError):resolve_addresses('example.test',443,1)
        self.assertEqual(cap.call_args.kwargs['timeout'],1)
        self.assertNotIn(DEMO_TOKEN,str(cap.call_args));self.assertNotIn('Authorization',str(cap.call_args))

    def test_slow_response_headers_do_not_reset_total_deadline(self):
        # A local raw TCP fixture deliberately sends header bytes slower than the
        # overall deadline but faster than a per-read timeout.
        import socketserver
        class Slow(socketserver.BaseRequestHandler):
            def handle(inner):
                inner.request.recv(8192)
                try:
                    inner.request.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    for _ in range(15):
                        time.sleep(.12);inner.request.sendall(b'x')
                except OSError:pass
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Slow)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            self.b._tools['docs']=HTTPRead(HTTPTransport(f'http://127.0.0.1:{server.server_address[1]}',allow_loopback=True,timeout_seconds=1),'/docs')
            cid=self.propose(approve=True);start=time.monotonic();r=self.execute(cid)
            self.assertEqual(r['result']['state'],'FAILED');self.assertLess(time.monotonic()-start,2.5)
        finally:server.shutdown();server.server_close();thread.join(timeout=2)

    def test_new_tool_argument_shapes_do_not_crash_broker(self):
        for value in [None,True,[],{},42]:
            r=self.call('propose_tool',{'tool_id':'docs','arguments':{'path':value,'query':{}}})
            self.assertFalse(r['ok'])
            r=self.call('propose_tool',{'tool_id':'github','arguments':{'repository':'example/project','terms':value,'per_page':1}})
            self.assertFalse(r['ok'])
        self.assertTrue(self.call('context')['ok'])
