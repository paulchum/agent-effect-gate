#!/usr/bin/env python3
"""Real Chromium + loopback HTTP reviewer acceptance, using disposable synthetic data.

Requires: uvicorn, playwright and a Chromium executable. No remote network requests.
Run from the source tree: PYTHONPATH=. python verification/reviewer_browser.py --output /tmp/aeg-ui
"""
from __future__ import annotations
import argparse
import asyncio
import re
import base64
import json
import secrets
import socket
import tempfile
import threading
import time
from pathlib import Path

from agent_effect_gate import Broker
from agent_effect_gate.broker import Sink
from agent_effect_gate.http_tools import HTTPRead, HTTPTransport, HTTPUpload
from agent_effect_gate.reviewer_auth import ReviewerAuth
from agent_effect_gate.reviewer_web import ReviewerApp


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--chromium', default='/usr/bin/chromium')
    parser.add_argument('--offline-asgi', action='store_true', help='Render supplied local assets and exercise ASGI in-process; no browser navigation or network')
    args = parser.parse_args()
    import uvicorn
    from playwright.sync_api import sync_playwright, expect
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='aeg-review-browser-') as temporary:
        deliveries = []
        now = [time.time()]
        broker = Broker(Path(temporary) / 'state.sqlite', secrets.token_bytes(32),
            clock=lambda: now[0],
            tools={'python_docs': HTTPRead(HTTPTransport('https://docs.python.org'), '/3', ()),
                   'report_upload': HTTPUpload(HTTPTransport('https://archive.example.com'), '/v1/reports')},
            sinks={'customer_archive': Sink('customer-controlled archive', '1', lambda payload, key: deliveries.append(payload))})
        tokens = broker.create_task('customer-workspace', 'customer', {'agents': ['main'], 'answer_mode': 'model', 'stage': 'deployment',
            'local_only': False, 'destinations': ['customer_archive'], 'max_requests': 1000, 'max_read_requests': 2000,
            'tool_grants': {'python_docs': {'approval': 'required', 'max_calls': 40},
                            'report_upload': {'approval': 'required', 'max_calls': 5}}})
        def call(id, op, arguments):
            result = broker.handle(tokens['main'], {'request_id': id, 'operation': op, 'arguments': arguments})
            assert result['ok'], result
            return result['result']
        tool = call('proposal-docs', 'propose_tool', {'tool_id': 'python_docs', 'arguments': {'path': '/3/library/json.html', 'query': {}}})['call_id']
        text = '<b>Customer report preview</b> — this is inert text, not active HTML.\nSynthetic customer acceptance fixture; no live data.'
        artifact = call('artifact', 'put_artifact', {'media_type': 'text/plain', 'data_b64': base64.b64encode(text.encode()).decode()})['artifact_id']
        release = call('release', 'propose_release', {'artifact_id': artifact, 'destination_id': 'customer_archive'})['proposal_id']
        upload = call('upload', 'propose_tool', {'tool_id': 'report_upload', 'arguments': {'artifact_id': artifact}})['call_id']
        password = secrets.token_urlsafe(32)
        ReviewerAuth(broker.store).set_user('alice-reviewer', password, ['customer-workspace'])
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(128)
        port = listener.getsockname()[1]; origin = f'http://127.0.0.1:{port}'
        app = ReviewerApp(broker, public_origin=origin)
        server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port,
                                               log_level='error', access_log=False, proxy_headers=False, lifespan='on'))
        thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True); thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline: raise RuntimeError('Reviewer server did not start')
            time.sleep(.05)
        errors = []
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=args.chromium, headless=True, args=['--no-sandbox'])
                # --no-sandbox applies ONLY to the disposable root-run TEST browser,
                # never to the broker's production code-execution sandbox.
                context = browser.new_context(viewport={'width': 1440, 'height': 1100})
                page = context.new_page(); page.on('pageerror', lambda error: errors.append(str(error)))
                if args.offline_asgi:
                    # Managed-browser network policy is preserved. This is an
                    # explicitly offline component test, not a navigation bypass.
                    cookie_jar = {'cookie': ''}
                    async def bridge(path, options):
                        headers = [(b'host', f'127.0.0.1:{port}'.encode())]
                        method = options.get('method', 'GET')
                        if method == 'POST': headers.append((b'origin', origin.encode()))
                        for key, value in options.get('headers', {}).items(): headers.append((key.lower().encode(), value.encode()))
                        if cookie_jar['cookie']: headers.append((b'cookie', cookie_jar['cookie'].encode()))
                        path, _, query = path.partition('?'); messages = []
                        async def receive(): return {'type': 'http.request', 'body': options.get('body', '').encode(), 'more_body': False}
                        async def send(message): messages.append(message)
                        await app({'type': 'http', 'method': method, 'path': path, 'query_string': query.encode(), 'headers': headers}, receive, send)
                        returned = dict(messages[0]['headers'])
                        if b'set-cookie' in returned: cookie_jar['cookie'] = returned[b'set-cookie'].decode().split(';')[0]
                        return {'status': messages[0]['status'], 'body': b''.join(m.get('body', b'') for m in messages).decode()}
                    page.expose_function('aegOfflineTestRequest', bridge)
                    assets = Path(__import__('agent_effect_gate').__file__).parent / 'web'
                    html = (assets / 'index.html').read_text()
                    html = re.sub(r'<link[^>]+>|<script[^>]*>.*?</script>', '', html, flags=re.S)
                    page.set_content(html)
                    page.add_style_tag(content=(assets / 'app.css').read_text())
                    page.evaluate('''() => { window.fetch = async (path, options = {}) => {
                        const reply = await window.aegOfflineTestRequest(path, options);
                        return {ok: reply.status >= 200 && reply.status < 300, status: reply.status, json: async () => JSON.parse(reply.body)};
                    }; }''')
                    page.add_script_tag(content=(assets / 'app.js').read_text())
                else:
                    page.goto(origin, wait_until='networkidle')
                expect(page.locator('#login')).to_be_visible()
                page.screenshot(path=str(args.output / 'review-login.png'), full_page=True)
                page.fill('#user', 'alice-reviewer'); page.fill('#password', password); page.click('#sign-in')
                expect(page.locator('#workspace')).to_be_visible(); expect(page.locator('#pending-count')).to_have_text('3')
                page.locator('.request-card').filter(has_text=tool).click(); expect(page.locator('#detail-title')).to_have_text('python_docs')
                expect(page.locator('#approve')).to_be_disabled(); expect(page.locator('#manifest')).to_contain_text('https://docs.python.org')
                page.screenshot(path=str(args.output / 'review-console.png'), full_page=True)
                page.check('#acknowledge'); expect(page.locator('#approve')).to_be_enabled(); page.click('#approve')
                expect(page.locator('#message')).to_contain_text('Approved by alice-reviewer')
                expect(page.locator('#detail-state')).to_have_text('APPROVED')
                with broker.store.transaction() as db:
                    assert db.execute('SELECT approver FROM tool_calls WHERE id=?', (tool,)).fetchone()[0] == 'alice-reviewer'
                    assert db.execute('SELECT count(*) FROM observations').fetchone()[0] == 0
                now[0] += 301
                page.click('#refresh')
                page.locator('.request-card').filter(has_text=tool).click()
                expect(page.locator('#approve')).to_have_text('Renew exact approval')
                expect(page.locator('#approve')).to_be_disabled()
                page.check('#acknowledge'); page.click('#approve')
                expect(page.locator('#detail-state')).to_have_text('APPROVED')
                assert broker.store.db.execute("SELECT count(*) FROM audit WHERE kind='tool_approval_renewed'").fetchone()[0] == 1
                page.locator('.request-card').filter(has_text=upload).click()
                expect(page.locator('#upload-preview')).to_be_visible()
                expect(page.locator('#upload-text')).to_have_text(text)
                assert page.locator('#upload-text b').count() == 0
                expect(page.locator('#payload-base64')).to_have_text(base64.b64encode(text.encode()).decode())
                expect(page.locator('#upload-meta')).to_contain_text(f'{len(text.encode())} bytes')
                page.screenshot(path=str(args.output / 'review-upload.png'), full_page=True)
                page.click('#reject'); expect(page.locator('#detail-state')).to_have_text('REVOKED')
                page.locator('.request-card').filter(has_text=release).click()
                expect(page.locator('#prepared')).to_contain_text('<b>Customer report preview</b>')
                assert page.locator('#prepared b').count() == 0
                page.click('#reject'); expect(page.locator('#detail-state')).to_have_text('REVOKED')
                assert deliveries == []
                page.set_viewport_size({'width': 390, 'height': 844}); page.screenshot(path=str(args.output / 'review-mobile.png'), full_page=True)
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile layout overflows'
                page.click('#logout'); expect(page.locator('#login')).to_be_visible()
                assert (page.evaluate("fetch('/api/queue').then(response => response.status)") if args.offline_asgi else context.request.get(origin + '/api/queue').status) == 401
                assert not errors, errors
                browser.close()
            result = {'passed': True, 'browser': 'Chromium', 'transport': 'offline ASGI bridge' if args.offline_asgi else 'real loopback HTTP',
                      'limitation': 'Browser HTTP navigation/cookie enforcement not tested in offline mode.' if args.offline_asgi else None, 'javascript_errors': errors,
                      'checks': ['login', 'task-scoped dashboard', 'queue selection', 'acknowledgement gate', 'exact approval',
                                 'authenticated audit actor', 'no automatic effect dispatch', 'inert payload preview', 'reject',
                                 'responsive mobile layout', 'expired approval renewal', 'HTTP upload exact inert UTF-8 preview',
                                 'HTTP upload base64 and byte length', 'logout session revocation'], 'external_requests': 0}
            (args.output / 'browser-results.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps(result, indent=2))
        finally:
            server.should_exit = True; thread.join(10); listener.close(); broker.close()


if __name__ == '__main__': main()
