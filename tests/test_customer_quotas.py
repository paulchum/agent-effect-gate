"""Customer regressions: bounded read storage, correct action budgets and token privacy."""
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from agent_effect_gate import Broker
from agent_effect_gate.codec import canonical, digest
from agent_effect_gate.http_tools import HTTPRead, HTTPTransport
from agent_effect_gate.runtime import run
from support import Case, KEY, policy


class ReadQuotas(Case):
    def configure(self, **kw):
        self.p = policy(answer_mode='model', fields=[], max_requests=10, max_read_requests=12, max_denials=1, **kw)
        self.b.replace_policy('task', self.p)

    def counters(self):
        return tuple(self.b.store.db.execute('SELECT requests,read_requests,denials,suspended FROM tasks WHERE id="task"').fetchone())

    def test_context_inbox_answer_and_tools_spend_only_reads(self):
        self.configure()
        for op in ['context', 'inbox', 'answer', 'list_tools']:
            self.assertTrue(self.call(op)['ok'])
        self.assertEqual(self.counters(), (0, 4, 0, 0))

    def test_read_schema_has_no_body_or_response_column(self):
        self.configure(); self.call('context')
        columns = {r[1] for r in self.b.store.db.execute('PRAGMA table_info(read_request_hashes)')}
        self.assertEqual(columns, {'task', 'agent', 'id', 'request_sha256'})
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM requests').fetchone()[0], 0)

    def test_successful_reads_do_not_append_audit_events(self):
        self.configure(); head = self.b.store.verify()
        for _ in range(12): self.assertTrue(self.call('inbox')['ok'])
        self.assertEqual(head, self.b.store.verify())

    def test_repeated_read_ids_still_consume_quota(self):
        self.configure()
        for _ in range(12): self.assertTrue(self.call('inbox', request_id='same')['ok'])
        self.assertEqual(self.call('inbox', request_id='same')['error'], 'read_budget_exhausted')
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM read_request_hashes').fetchone()[0], 1)

    def test_read_quota_is_shared_across_agents(self):
        self.configure()
        for _ in range(6): self.call('inbox', agent='main'); self.call('inbox', agent='worker')
        self.assertEqual(self.call('inbox', agent='isolated')['error'], 'read_budget_exhausted')
        self.assertEqual(self.counters(), (0, 12, 0, 0))

    def test_exhausted_action_budget_preserves_read_quota(self):
        self.configure()
        for _ in range(10): self.artifact(b'x')
        self.assertEqual(self.call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='})['error'], 'request_budget_exhausted')
        self.assertTrue(self.call('context')['ok']); self.assertEqual(self.counters(), (10, 1, 0, 0))

    def test_exhausted_reads_preserve_action_quota(self):
        self.configure()
        for _ in range(12): self.call('inbox')
        self.assertEqual(self.call('context')['error'], 'read_budget_exhausted')
        self.artifact(); self.assertEqual(self.counters(), (1, 12, 0, 0))

    def test_3000_over_quota_inbox_calls_make_zero_database_changes(self):
        self.configure()
        for _ in range(10): self.artifact(b'x')
        for _ in range(12): self.call('inbox')
        head = self.b.store.verify(); before = self.b.store.db.total_changes
        pages = self.b.store.db.execute('PRAGMA page_count').fetchone()[0]
        for _ in range(3000):
            self.assertEqual(self.call('inbox')['error'], 'read_budget_exhausted')
        self.assertEqual(self.b.store.db.total_changes, before)
        self.assertEqual(self.b.store.verify(), head)
        self.assertEqual(self.b.store.db.execute('PRAGMA page_count').fetchone()[0], pages)
        self.assertEqual(self.counters(), (10, 12, 0, 0))

    def test_action_exhaustion_is_not_a_security_denial(self):
        self.configure()
        for _ in range(10): self.artifact(b'x')
        before = self.b.store.db.total_changes
        for _ in range(100): self.call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='})
        self.assertEqual(self.counters(), (10, 0, 0, 0)); self.assertEqual(self.b.store.db.total_changes, before)

    def test_read_hash_conflicts_cannot_replace_original_hash(self):
        self.configure(); self.call('inbox', request_id='key')
        before = self.b.store.db.execute('SELECT request_sha256 FROM read_request_hashes').fetchone()[0]
        self.assertEqual(self.call('context', request_id='key')['error'], 'request_id_conflict')
        self.assertEqual(self.b.store.db.execute('SELECT request_sha256 FROM read_request_hashes').fetchone()[0], before)

    def test_read_write_id_conflict_does_not_execute(self):
        self.configure(); self.call('inbox', request_id='key')
        response = self.call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='}, request_id='key')
        self.assertEqual(response['error'], 'request_id_conflict')
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0], 0)

    def test_host_snapshots_are_nonpersistent_and_unmetered(self):
        self.configure(); before = self.b.store.db.total_changes; head = self.b.store.verify()
        for _ in range(100):
            self.assertTrue(self.b.host_view(self.tokens['main'], 'context')['ok'])
            self.assertTrue(self.b.host_view(self.tokens['main'], 'answer')['ok'])
        self.assertEqual(self.b.store.db.total_changes, before); self.assertEqual(self.b.store.verify(), head)
        self.assertEqual(self.counters(), (0, 0, 0, 0))

    def test_host_evidence_answer_does_not_emit_missing_evidence_incidents(self):
        before = self.b.store.db.total_changes
        self.assertTrue(self.b.host_view(self.tokens['main'], 'answer')['ok'])
        self.assertEqual(before, self.b.store.db.total_changes)

    def test_host_view_cannot_be_invoked_by_agent(self):
        self.assertEqual(self.call('host_view', {'operation': 'context'})['error'], 'unknown_operation')
        with self.assertRaises(ValueError): self.b.host_view(self.tokens['main'], 'execute_tool')
        self.assertFalse(self.b.host_view('not-a-session', 'context')['ok'])

    def test_runtime_ten_action_budget_provides_ten_actions(self):
        self.configure()
        class Adapter:
            calls = 0
            def propose(inner, context, last):
                inner.calls += 1
                return {'request_id': 'model-' + str(inner.calls), 'operation': 'put_artifact',
                        'arguments': {'media_type': 'text/plain', 'data_b64': 'eA=='}}
        adapter = Adapter(); result = run(adapter, self.b, self.tokens['main'], max_steps=20)
        self.assertEqual(result['runtime']['reason'], 'request_budget_exhausted')
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0], 10)
        self.assertEqual(self.counters(), (10, 0, 0, 0)); self.assertEqual(adapter.calls, 10)

    def test_runtime_read_exhaustion_pauses_without_suspension(self):
        self.configure()
        class Adapter:
            n = 0
            def propose(inner, context, last):
                inner.n += 1
                return {'request_id': 'read-' + str(inner.n), 'operation': 'inbox', 'arguments': {}}
        result = run(Adapter(), self.b, self.tokens['main'], max_steps=20)
        self.assertEqual(result['runtime']['reason'], 'read_budget_exhausted')
        self.assertEqual(self.counters(), (0, 12, 0, 0))

    def test_runtime_failure_notice_is_deduplicated(self):
        self.configure()
        class Broken:
            def propose(self, context, last): raise RuntimeError('private provider detail')
        first = run(Broken(), self.b, self.tokens['main']); head = self.b.store.verify()
        for _ in range(10): run(Broken(), self.b, self.tokens['main'])
        self.assertEqual(self.b.store.verify(), head)
        self.assertEqual(first['runtime']['status'], 'failed')
        self.assertNotIn('private provider detail', json.dumps(first))

    def test_concurrent_connections_cannot_overspend_read_quota(self):
        self.configure(); other = Broker(self.path, KEY, clock=self.clock)
        try:
            def call(i):
                b = self.b if i % 2 else other
                return b.handle(self.tokens['main'], {'request_id': f'parallel-{i}', 'operation': 'inbox', 'arguments': {}})
            with ThreadPoolExecutor(max_workers=8) as pool: results = list(pool.map(call, range(60)))
            self.assertEqual(sum(r['ok'] for r in results), 12)
            self.assertEqual(self.counters(), (0, 12, 0, 0))
        finally: other.close()

    def test_actual_legacy_read_cache_migrates_once_and_refunds_actions(self):
        self.configure(); self.b.close()
        # Reconstruct the old on-disk shape using authenticated historical events.
        b = Broker(self.path, KEY, clock=self.clock)
        with b.store.transaction() as db:
            db.execute("DELETE FROM schema_migrations WHERE version='read-quotas-v1'")
            db.execute('ALTER TABLE tasks DROP COLUMN read_requests')
            db.execute('UPDATE tasks SET requests=3 WHERE id="task"')
            for i in range(3):
                req = {'request_id': f'legacy-{i}', 'operation': 'inbox', 'arguments': {}}
                sha = digest(canonical(req))
                db.execute('INSERT INTO requests VALUES(?,?,?,?,?)', ('task', 'main', req['request_id'], sha, json.dumps({'ok': True, 'result': {'messages': ['large legacy body' * 100]}})))
                b.store.append(db, 'task', 'main', 'action_allowed', {'operation': 'inbox', 'request_sha256': sha})
        b.close(); self.b = Broker(self.path, KEY, clock=self.clock)
        self.assertEqual(self.counters(), (0, 3, 0, 0))
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM requests').fetchone()[0], 0)
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM read_request_hashes').fetchone()[0], 3)
        anchor = self.b.store.verify(); self.b.close(); self.b = Broker(self.path, KEY, clock=self.clock)
        self.assertEqual(self.counters(), (0, 3, 0, 0)); self.assertEqual(self.b.store.verify(), anchor)


class CredentialPrivacy(Case):
    def setUp(self):
        super().setUp()
        self.secret = 'weak-token-repeated-weak-token'
        self.adapter = HTTPRead(HTTPTransport('https://docs.python.org', credential=self.secret), '/3', ())
        self.b._tools = {'docs': self.adapter}
        self.p = policy(answer_mode='model', fields=[], local_only=False, tool_grants={'docs': {'approval': 'required', 'max_calls': 8}})
        self.b.replace_policy('task', self.p)

    def proposal(self, request_id='prepare'):
        result = self.call('propose_tool', {'tool_id': 'docs', 'arguments': {'path': '/3/index.html', 'query': {}}}, request_id=request_id)
        self.assertTrue(result['ok'], result); return result

    def assert_private(self, response):
        text = json.dumps(response)
        self.assertNotIn(self.secret, text)
        self.assertNotIn(hashlib.sha256(self.secret.encode()).hexdigest(), text)
        self.assertNotIn('credential_binding', text)

    def test_tool_discovery_omits_secret_and_unkeyed_fingerprint(self): self.assert_private(self.call('list_tools'))
    def test_proposal_and_review_omit_secret_and_unkeyed_fingerprint(self):
        response = self.proposal(); self.assert_private(response)
        self.assert_private(self.b.review_tool(response['result']['call_id']))
        self.assert_private(self.call('context'))

    def test_private_approval_binding_is_keyed(self):
        self.proposal()
        manifest = self.b.store.db.execute('SELECT manifest FROM tool_calls').fetchone()[0]
        self.assertIn('credential_binding', manifest)
        self.assertNotIn(hashlib.sha256(self.secret.encode()).hexdigest(), manifest)
        self.assertEqual(self.b._private_tool_manifest(self.adapter), self.b._private_tool_manifest(self.adapter))

    def test_old_cached_proposal_cannot_reexpose_fingerprint(self):
        response = self.proposal(); old = json.loads(json.dumps(response))
        old['result']['manifest']['credential_binding'] = hashlib.sha256(self.secret.encode()).hexdigest()
        with self.b.store.transaction() as db: db.execute('UPDATE requests SET response=? WHERE id="prepare"', (json.dumps(old),))
        self.assert_private(self.proposal())

    def test_credential_rotation_invalidates_existing_approval(self):
        response = self.proposal(); cid = response['result']['call_id']; self.b.approve_tool(cid, reviewer='reviewer')
        self.b._tools['docs'] = HTTPRead(HTTPTransport('https://docs.python.org', credential=self.secret + '-rotated'), '/3', ())
        r = self.call('execute_tool', {'call_id': cid})
        self.assertFalse(r['ok']); self.assertIn('changed', r['error'])
