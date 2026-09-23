#!/usr/bin/env python3
"""Real HTTP + installed reviewer CLI smoke; only synthetic loopback state.

Run as non-root with the installed review extra. This is HTTP transport testing,
not a replacement for HTTPS and cookie enforcement in the customer's browser.
"""
import http.cookiejar
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from agent_effect_gate import __version__
from agent_effect_gate.cli import initialize, _broker


def main():
    if os.geteuid() == 0: raise SystemExit('Run as a dedicated non-root service account.')
    with tempfile.TemporaryDirectory(prefix='aeg-review-http-') as temporary:
        root = Path(temporary); state = root / 'state'; config = root / 'config.json'; anchor = root / 'anchor.json'
        config.write_text(json.dumps({'task_id': 'customer-task', 'tenant_id': 'customer', 'sources': [],
            'policy': {'agents': ['main'], 'answer_mode': 'model', 'local_only': False, 'stage': 'deployment',
                       'tool_grants': {'docs': {'approval': 'required', 'max_calls': 4}}},
            'tools': [{'id': 'docs', 'kind': 'http_read', 'origin': 'https://docs.python.org', 'path_prefix': '/3', 'query_keys': []}]}))
        password = secrets.token_urlsafe(32)
        initialized = initialize(state, config, reviewer=('reviewer', password)); anchor.write_text(json.dumps(initialized['audit_head']))
        broker = _broker(state)
        try:
            cid = broker.handle((state / 'sessions/main.token').read_text(), {'request_id': 'proposal', 'operation': 'propose_tool',
                'arguments': {'tool_id': 'docs', 'arguments': {'path': '/3/index.html', 'query': {}}}})['result']['call_id']
        finally: broker.close()
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'; jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
        csrf = None
        def request(path, payload=None, origin_override=None, csrf_enabled=True):
            headers = {}
            if payload is not None:
                headers.update({'Content-Type': 'application/json', 'Origin': origin_override or origin})
                if csrf and csrf_enabled: headers['X-CSRF-Token'] = csrf
            wire = urllib.request.Request(origin + path, data=None if payload is None else json.dumps(payload).encode(), headers=headers)
            try: response = client.open(wire, timeout=5)
            except urllib.error.HTTPError as error: response = error
            with response:
                raw = response.read(); body = json.loads(raw) if response.headers.get_content_type() == 'application/json' else raw.decode()
                return response.status, body, response.headers
        process = subprocess.Popen([sys.executable, '-I', '-m', 'agent_effect_gate', 'review', '--state', str(state), '--port', str(port),
                                    '--anchor', str(anchor), '--production'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root)
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    if request('/healthz')[0] == 200: break
                except OSError: pass
                if process.poll() is not None or time.monotonic() > deadline: raise RuntimeError('Installed reviewer service did not start')
                time.sleep(.05)
            status, html, headers = request('/'); assert status == 200 and 'Review Console' in html
            assert "default-src 'none'" in headers['Content-Security-Policy']
            assert request('/app.js')[0] == 200 and request('/app.css')[0] == 200
            assert request('/api/queue')[0] == 401
            status, session, headers = request('/api/login', {'username': 'reviewer', 'password': password})
            assert status == 200 and session['username'] == 'reviewer'; csrf = session['csrf']
            assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']
            assert request('/api/queue')[1]['items'][0]['id'] == cid
            detail = request('/api/review/tool/' + cid)[1]
            decision = {'kind': 'tool', 'id': cid, 'decision': 'approve', 'review_token': detail['review_token']}
            assert request('/api/decision', decision, csrf_enabled=False)[0] == 403
            assert request('/api/decision', decision, origin_override='https://not-the-console.example')[0] == 403
            assert request('/api/decision', {**decision, 'reviewer': 'forged'})[0] == 400
            assert request('/api/decision', decision)[1]['state'] == 'APPROVED'
            detail = request('/api/review/tool/' + cid)[1]; assert detail['approver'] == 'reviewer'
            assert request('/api/decision', decision)[0] == 409
            assert request('/api/logout', {})[0] == 200; assert request('/api/queue')[0] == 401
            process.terminate(); out, error = process.communicate(timeout=10); assert process.returncode in (0, -signal.SIGTERM), error
            assert 'Application shutdown complete' in error
            assert not out.strip(), 'Reviewer server must not emit customer payloads to stdout'
        finally:
            if process.poll() is None: process.kill(); process.wait()
        print(json.dumps({'passed': True, 'package_version': __version__, 'non_root': True,
            'installed_location': __import__('agent_effect_gate').__file__, 'transport': 'real loopback HTTP through installed CLI/Uvicorn',
            'checks': ['health', 'installed_assets', 'security_headers', 'unauthenticated_refusal', 'login_cookie', 'queue',
                       'CSRF', 'Origin', 'forged_identity_refusal', 'authenticated_approval', 'stale_view_refusal', 'logout', 'clean_shutdown'],
            'browser_TLS_qualification': 'not exercised', 'external_requests': 0}, indent=2))


if __name__ == '__main__': main()
