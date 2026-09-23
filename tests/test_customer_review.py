"""Authenticated reviewer boundary, session lifecycle and browser API contract."""
import asyncio
import json
from agent_effect_gate.codec import IntegrityError, Rejected, canonical
from agent_effect_gate.http_tools import HTTPRead, HTTPTransport
from agent_effect_gate.reviewer_auth import ReviewerAuth, AuthError, IDLE_SECONDS, SESSION_SECONDS, password_hash, verify_password
from agent_effect_gate.reviewer_service import ReviewerService
from agent_effect_gate.reviewer_web import ReviewerApp
from support import Case, policy

PASSWORD = 'synthetic-reviewer-password-only-for-tests'


class Accounts(Case):
    def setUp(self):
        super().setUp(); self.auth = ReviewerAuth(self.b.store); self.auth.set_user('alice', PASSWORD, ['task'])
    def login(self): return self.auth.login('alice', PASSWORD)
    def test_password_is_salted_scrypt_not_plaintext_or_fast_digest(self):
        row = self.b.store.db.execute('SELECT password_hash FROM reviewer_users').fetchone()[0]
        self.assertTrue(row.startswith('scrypt-v1$')); self.assertNotIn(PASSWORD, row)
        self.assertTrue(verify_password(PASSWORD, row)); self.assertNotEqual(row, password_hash(PASSWORD))
    def test_short_password_and_unscoped_accounts_are_refused(self):
        with self.assertRaises(ValueError): self.auth.set_user('short', 'short', ['task'])
        with self.assertRaises(ValueError): self.auth.set_user('scopeless', PASSWORD, [])
    def test_login_resolves_identity_and_task_grants(self):
        token, reviewer = self.login(); self.assertEqual(reviewer.username, 'alice'); self.assertEqual(reviewer.tasks, ('task',))
        self.assertEqual(self.auth.authenticate(token), reviewer)
        row = dict(self.b.store.db.execute('SELECT * FROM reviewer_sessions').fetchone())
        self.assertNotIn(token, json.dumps(row)); self.assertNotIn(PASSWORD, json.dumps(row))
    def test_wrong_or_unknown_user_cannot_log_in(self):
        for name in ['alice', 'unknown']:
            with self.assertRaises(AuthError): self.auth.login(name, 'incorrect-password')
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM reviewer_sessions').fetchone()[0], 0)
    def test_agent_token_is_not_a_reviewer_session(self):
        with self.assertRaises(AuthError): self.auth.authenticate(self.tokens['main'])
    def test_unknown_user_failures_do_not_create_rows_or_audit_events(self):
        head = self.b.store.verify(); changes = self.b.store.db.total_changes
        with self.assertRaises(AuthError): self.auth.login('untrusted-unknown-user', PASSWORD)
        self.assertEqual(head, self.b.store.verify()); self.assertEqual(changes, self.b.store.db.total_changes)
    def test_known_account_lockout_persists_across_auth_instances(self):
        for _ in range(5):
            with self.assertRaises(AuthError): self.auth.login('alice', 'incorrect-password')
        with self.assertRaises(AuthError): ReviewerAuth(self.b.store).login('alice', PASSWORD)
        self.clock.advance(901); self.assertEqual(ReviewerAuth(self.b.store).login('alice', PASSWORD)[1].username, 'alice')
    def test_process_login_limiter_has_fixed_capacity(self):
        self.auth._tokens = 0; self.auth._refilled += 100
        with self.assertRaisesRegex(AuthError, 'rate_limited'): self.login()
    def test_session_count_is_bounded_per_reviewer(self):
        for _ in range(6): self.clock.advance(1); self.login()
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM reviewer_sessions').fetchone()[0], 4)
    def test_logout_revokes_session_immediately(self):
        token, reviewer = self.login(); self.auth.logout(reviewer)
        with self.assertRaises(AuthError): self.auth.authenticate(token)
    def test_idle_timeout_expires_session(self):
        token, _ = self.login(); self.clock.advance(IDLE_SECONDS + 1)
        with self.assertRaises(AuthError): self.auth.authenticate(token)
    def test_session_refresh_does_not_extend_absolute_expiry(self):
        token, _ = self.login()
        for _ in range(SESSION_SECONDS // 600):
            self.clock.advance(600)
            if self.clock() < 1800000000 + SESSION_SECONDS: self.auth.authenticate(token)
        with self.assertRaises(AuthError): self.auth.authenticate(token)
    def test_password_reset_and_disable_revoke_all_sessions(self):
        token, _ = self.login(); self.auth.set_user('alice', PASSWORD + '-new', ['task'])
        with self.assertRaises(AuthError): self.auth.authenticate(token)
        token, _ = self.auth.login('alice', PASSWORD + '-new'); self.auth.disable('alice')
        with self.assertRaises(AuthError): self.auth.authenticate(token)
        with self.assertRaises(AuthError): self.auth.login('alice', PASSWORD + '-new')
    def test_role_and_session_tampering_fail_integrity_checks(self):
        token, _ = self.login()
        self.b.store.db.execute('UPDATE reviewer_users SET task_scope=?', ('["unauthorized"]',))
        with self.assertRaises(IntegrityError): self.auth.authenticate(token)
    def test_session_expiry_tampering_fails_integrity_check(self):
        token, _ = self.login(); self.b.store.db.execute('UPDATE reviewer_sessions SET expires_at=expires_at+9999')
        with self.assertRaises(IntegrityError): self.auth.authenticate(token)


class ReviewAPI(Case):
    def setUp(self):
        super().setUp()
        self.b._tools = {'docs': HTTPRead(HTTPTransport('https://docs.python.org'), '/3', ())}
        self.p = policy(answer_mode='model', fields=[], local_only=False, tool_grants={'docs': {'approval': 'required', 'max_calls': 50}})
        self.b.replace_policy('task', self.p)
        self.b.create_task('other-task', 'other-tenant', policy(answer_mode='model', fields=[]))
        self.app = ReviewerApp(self.b); self.auth = self.app.auth
        self.auth.set_user('alice', PASSWORD, ['task']); self.token, self.reviewer = self.auth.login('alice', PASSWORD)
        self.service = self.app.service
    def proposal(self):
        response = self.call('propose_tool', {'tool_id': 'docs', 'arguments': {'path': '/3/index.html', 'query': {}}})
        self.assertTrue(response['ok'], response); return response['result']['call_id']
    def request(self, method, path, payload=None, *, auth=True, csrf=True, origin='http://127.0.0.1:8765', host='127.0.0.1:8765', more_headers=None, raw=None):
        headers = [(b'host', host.encode())]
        if origin is not None: headers.append((b'origin', origin.encode()))
        if auth: headers.append((b'cookie', f'{self.app.cookie_name}={self.token}'.encode()))
        if csrf: headers.append((b'x-csrf-token', self.reviewer.csrf.encode()))
        if method == 'POST': headers.append((b'content-type', b'application/json'))
        headers += more_headers or []
        body = raw if raw is not None else canonical(payload if payload is not None else {})
        path, _, query = path.partition('?'); messages = []
        async def receive(): return {'type': 'http.request', 'body': body, 'more_body': False}
        async def send(message): messages.append(message)
        asyncio.run(self.app({'type': 'http', 'method': method, 'path': path, 'query_string': query.encode(), 'headers': headers}, receive, send))
        content = b''.join(m.get('body', b'') for m in messages)
        out_headers = dict(messages[0]['headers'])
        return messages[0]['status'], json.loads(content) if out_headers.get(b'content-type', b'').startswith(b'application/json') else content.decode(), out_headers
    def decision(self, cid, **kw):
        view = self.service.detail(self.reviewer, 'tool', cid)
        return {'kind': 'tool', 'id': cid, 'decision': 'approve', 'review_token': view['review_token'], **kw}
    def test_anonymous_queue_session_and_decision_are_refused(self):
        for path in ['/api/session', '/api/queue', '/api/overview']:
            self.assertEqual(self.request('GET', path, auth=False)[0], 401)
        self.assertEqual(self.request('POST', '/api/decision', {}, auth=False)[0], 401)
    def test_login_returns_http_only_same_site_cookie_and_session_identity(self):
        status, body, headers = self.request('POST', '/api/login', {'username': 'alice', 'password': PASSWORD}, auth=False)
        self.assertEqual(status, 200); self.assertEqual(body['username'], 'alice')
        self.assertIn(b'HttpOnly', headers[b'set-cookie']); self.assertIn(b'SameSite=Strict', headers[b'set-cookie'])
        self.assertNotIn('password', body)
    def test_https_cookie_has_secure_host_prefix(self):
        app = ReviewerApp(self.b, public_origin='https://review.example.test')
        self.assertTrue(app.cookie_name.startswith('__Host-')); self.assertIn('; Secure', app._cookie('x'))
    def test_external_http_origin_is_refused_at_startup(self):
        with self.assertRaises(ValueError): ReviewerApp(self.b, public_origin='http://review.example.test')
    def test_mutations_require_same_origin_and_csrf(self):
        cid = self.proposal(); payload = self.decision(cid)
        self.assertEqual(self.request('POST', '/api/decision', payload, csrf=False)[0], 403)
        self.assertEqual(self.request('POST', '/api/decision', payload, origin=None)[0], 403)
        self.assertEqual(self.request('POST', '/api/decision', payload, origin='https://different.example')[0], 403)
        self.assertEqual(self.b.review_tool(cid)['state'], 'PENDING')
    def test_dns_rebinding_host_and_duplicate_headers_are_refused(self):
        self.assertEqual(self.request('GET', '/api/queue', host='different.example')[0], 403)
        self.assertEqual(self.request('GET', '/api/queue', more_headers=[(b'host', b'127.0.0.1:8765')])[0], 400)
    def test_http_api_cannot_supply_a_reviewer_name(self):
        cid = self.proposal()
        self.assertEqual(self.request('POST', '/api/decision', self.decision(cid, reviewer='forged'))[0], 400)
        self.assertEqual(self.b.review_tool(cid)['state'], 'PENDING')
    def test_approval_uses_authenticated_identity_and_never_dispatches(self):
        cid = self.proposal(); status, body, _ = self.request('POST', '/api/decision', self.decision(cid))
        self.assertEqual(status, 200); self.assertEqual(body['state'], 'APPROVED')
        self.assertEqual(self.service.detail(self.reviewer, 'tool', cid)['approver'], 'alice')
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM observations').fetchone()[0], 0)
        rows = [dict(r) for r in self.b.store.db.execute("SELECT * FROM audit WHERE kind='tool_approved'")]
        self.assertTrue(rows); self.assertEqual(rows[-1]['agent'], 'alice')
    def test_stale_review_after_state_change_requires_refresh(self):
        cid = self.proposal(); payload = self.decision(cid); self.b.approve_tool(cid, reviewer='operator')
        self.assertEqual(self.request('POST', '/api/decision', payload)[0], 409)
    def test_stale_review_after_policy_change_requires_refresh(self):
        cid = self.proposal(); payload = self.decision(cid); self.b.replace_policy('task', self.p)
        self.assertEqual(self.request('POST', '/api/decision', payload)[0], 409)
    def test_rejection_and_revocation_have_authenticated_actor(self):
        cid = self.proposal(); self.assertEqual(self.request('POST', '/api/decision', self.decision(cid, decision='reject'))[0], 200)
        self.assertEqual(self.b.review_tool(cid)['state'], 'REVOKED')
        cid = self.proposal(); self.request('POST', '/api/decision', self.decision(cid))
        self.assertEqual(self.request('POST', '/api/decision', self.decision(cid, decision='reject'))[0], 200)
        self.assertEqual(self.b.review_tool(cid)['state'], 'REVOKED')
    def test_task_scope_filters_dashboard_queue_and_detail(self):
        cid = self.proposal(); self.auth.set_user('bob', PASSWORD, ['other-task']); _, bob = self.auth.login('bob', PASSWORD)
        self.assertEqual([t['id'] for t in self.service.overview(bob)['tasks']], ['other-task'])
        self.assertEqual(self.service.queue(bob)['items'], [])
        with self.assertRaisesRegex(Rejected, 'review_not_found'): self.service.detail(bob, 'tool', cid)
    def test_queue_is_paginated_and_invalid_filter_is_refused(self):
        for _ in range(27): self.proposal()
        page = self.service.queue(self.reviewer); self.assertEqual(len(page['items']), 25); self.assertEqual(page['next_offset'], 25)
        self.assertEqual(len(self.service.queue(self.reviewer, offset=25)['items']), 2)
        self.assertEqual(self.request('GET', '/api/queue?state=unknown')[0], 400)
    def test_ui_static_security_headers_and_inert_text_rendering(self):
        status, body, headers = self.request('GET', '/', auth=False)
        self.assertEqual(status, 200); self.assertIn('<title>Review Console', body)
        self.assertIn(b"default-src 'none'", headers[b'content-security-policy']); self.assertEqual(headers[b'x-frame-options'], b'DENY')
        js = self.request('GET', '/app.js', auth=False)[1]
        self.assertIn('.textContent', js); self.assertNotIn('.innerHTML =', js); self.assertNotIn('localStorage', js)
    def test_logout_removes_session_and_cookie(self):
        status, _, headers = self.request('POST', '/api/logout', {})
        self.assertEqual(status, 200); self.assertIn(b'Max-Age=0', headers[b'set-cookie'])
        self.assertEqual(self.request('GET', '/api/session')[0], 401)
    def test_large_body_is_rejected_without_account_side_effects(self):
        before = self.b.store.db.total_changes
        self.assertEqual(self.request('POST', '/api/login', raw=b'x' * 8193, auth=False)[0], 413)
        self.assertEqual(before, self.b.store.db.total_changes)
    def test_tampered_reviewer_grants_stop_service(self):
        self.b.store.db.execute('UPDATE reviewer_users SET disabled=1')
        self.assertEqual(self.request('GET', '/api/overview')[0], 503)
        self.assertEqual(self.request('GET', '/healthz', auth=False)[0], 503)
    def test_reviewer_reads_do_not_spend_agent_quota_or_append_read_audit(self):
        before = self.b.store.db.total_changes; head = self.b.store.verify()
        for _ in range(10): self.request('GET', '/api/queue'); self.request('GET', '/api/overview')
        self.assertEqual(self.b.store.db.total_changes, before); self.assertEqual(head, self.b.store.verify())
