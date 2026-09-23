import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

from agent_effect_gate import Broker, IntegrityError, Rejected
from agent_effect_gate.broker import Sink
from support import Case, KEY


class Releases(Case):
    def test_unapproved_release_never_dispatches(self):
        p = self.proposal()
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['error'], 'approval_required')
        self.assertEqual(self.deliveries, [])

    def test_model_cannot_approve_or_smuggle_approval(self):
        p = self.proposal()
        self.assertFalse(self.call('approve_release', {'proposal_id': p, 'reviewer': 'admin'})['ok'])
        self.assertEqual(self.call('execute_release', {'proposal_id': p, 'approved': True})['error'], 'invalid_schema')
        self.assertEqual(self.deliveries, [])

    def test_approved_exact_bytes_dispatch_once(self):
        p = self.proposal(approved=True)
        self.assertEqual(self.b.review_payload(p), b'private example')
        result = self.call('execute_release', {'proposal_id': p})
        self.assertEqual(result['result']['state'], 'DELIVERED')
        for _ in range(5): self.call('execute_release', {'proposal_id': p})
        self.assertEqual(self.deliveries, [(b'private example', p)])

    def test_approval_expiry(self):
        p = self.proposal(approved=True)
        self.clock.advance(300)
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['error'], 'approval_expired')
        self.assertEqual(self.deliveries, [])

    def test_policy_change_invalidates_approval(self):
        p = self.proposal(approved=True)
        self.b.replace_policy('task', self.p)
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['error'], 'approval_binding_changed')
        self.assertEqual(self.deliveries, [])

    def test_return_to_local_only_blocks_existing_approval(self):
        p = self.proposal(approved=True)
        self.p.update(local_only=True, destinations=[])
        self.b.replace_policy('task', self.p)
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['error'], 'local_only')
        self.assertEqual(self.deliveries, [])

    def test_destination_manifest_change_invalidates_approval(self):
        p = self.proposal(approved=True)
        self.b._sinks['approved_sink'] = Sink('different-audience', '1', self.send)
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['error'], 'approval_binding_changed')
        self.assertEqual(self.deliveries, [])

    def test_unknown_destination_not_proposable(self):
        self.allow_release(); a = self.artifact()
        r = self.call('propose_release', {'artifact_id': a, 'destination_id': 'other'})
        self.assertEqual(r['error'], 'destination_not_allowed')

    def test_missing_adapter_not_proposable(self):
        self.allow_release(); a = self.artifact(); self.b._sinks.clear()
        r = self.call('propose_release', {'artifact_id': a, 'destination_id': 'approved_sink'})
        self.assertEqual(r['error'], 'destination_unavailable')

    def test_approval_is_bound_to_agent(self):
        p = self.proposal(approved=True)
        self.assertEqual(self.call('execute_release', {'proposal_id': p}, agent='worker')['error'], 'proposal_not_found')
        self.assertEqual(self.deliveries, [])

    def test_approval_is_bound_to_task(self):
        p = self.proposal(approved=True)
        other = self.b.create_task('other', 'tenant', self.p)
        self.assertEqual(self.call('execute_release', {'proposal_id': p}, token=other['main'])['error'], 'proposal_not_found')
        self.assertEqual(self.deliveries, [])

    def test_revocation_before_dispatch(self):
        p = self.proposal(approved=True)
        self.b.revoke_release(p, reviewer='admin')
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['result']['state'], 'REVOKED')
        self.assertEqual(self.deliveries, [])

    def test_approval_ttl_cannot_exceed_policy(self):
        p = self.proposal()
        with self.assertRaises(Rejected): self.b.approve_release(p, reviewer='admin', ttl_seconds=301)

    def test_reviewer_cannot_double_approve(self):
        p = self.proposal(approved=True)
        with self.assertRaises(Rejected): self.b.approve_release(p, reviewer='admin')

    def test_approval_cannot_happen_while_suspended(self):
        p = self.proposal()
        self.b.set_suspended('task', True, operator='admin')
        with self.assertRaises(Rejected): self.b.approve_release(p, reviewer='admin')

    def test_approval_record_tamper_fails_closed(self):
        p = self.proposal(approved=True)
        self.b.store.db.execute('UPDATE proposals SET expires_at=expires_at+999')
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['error'], 'integrity_or_storage_failure')
        self.assertEqual(self.deliveries, [])

    def test_proposal_bytes_binding_tamper_fails_closed(self):
        p = self.proposal(approved=True)
        self.b.store.db.execute("UPDATE proposals SET payload_sha256=?", ('0'*64,))
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['error'], 'integrity_or_storage_failure')
        self.assertEqual(self.deliveries, [])

    def test_ambiguous_adapter_result_is_not_retried(self):
        def ambiguous(payload, request_id):
            self.deliveries.append((payload, request_id))
            raise TimeoutError('private secret must not be copied to output')
        self.b._sinks['approved_sink'] = Sink('approved-example-audience', '1', ambiguous)
        p = self.proposal(approved=True)
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['result']['state'], 'UNKNOWN')
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['result']['state'], 'UNKNOWN')
        self.assertEqual(len(self.deliveries), 1)
        answer = self.answer()
        self.assertTrue(any(n['code'] == 'release_outcome_unknown' for n in answer['notices']))
        self.assertNotIn('private secret', str(answer))

    def test_crash_after_dispatch_intent_survives_restart_without_retry(self):
        def crash(payload, request_id):
            self.deliveries.append((payload, request_id))
            raise SystemExit('simulated process interruption')
        self.b._sinks['approved_sink'] = Sink('approved-example-audience', '1', crash)
        p = self.proposal(approved=True)
        with self.assertRaises(SystemExit): self.call('execute_release', {'proposal_id': p})
        self.b.close()
        self.b = Broker(self.path, KEY, clock=self.clock, sinks={'approved_sink': self.sink})
        r = self.call('execute_release', {'proposal_id': p})['result']
        self.assertEqual(r['state'], 'DISPATCHING')
        self.assertEqual(r['outcome'], 'unknown_or_in_progress')
        self.assertEqual(len(self.deliveries), 1)

    def test_concurrent_requests_only_one_dispatch(self):
        p = self.proposal(approved=True)
        def run(i):
            return self.b.handle(self.tokens['main'], {'request_id': f'concurrent-{i}',
                                 'operation': 'execute_release', 'arguments': {'proposal_id': p}})
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(run, range(16)))
        self.assertTrue(all(r['ok'] for r in responses), responses)
        self.assertEqual(len(self.deliveries), 1)

    def test_multiple_broker_instances_only_one_dispatch(self):
        p = self.proposal(approved=True)
        second = Broker(self.path, KEY, clock=self.clock, sinks={'approved_sink': self.sink})
        try:
            barrier = threading.Barrier(2)
            def run(which):
                barrier.wait()
                broker = self.b if which == 0 else second
                return broker.handle(self.tokens['main'], {'request_id': f'process-{which}',
                                     'operation': 'execute_release', 'arguments': {'proposal_id': p}})
            with ThreadPoolExecutor(max_workers=2) as pool: responses = list(pool.map(run, range(2)))
            self.assertTrue(all(r['ok'] for r in responses), responses)
            self.assertEqual(len(self.deliveries), 1)
        finally: second.close()

    def test_dispatch_intent_is_durable_before_sink(self):
        seen = []
        def check(payload, request_id):
            other = sqlite3.connect(self.path)
            try:
                row = other.execute("SELECT state FROM proposals WHERE id=?", (request_id,)).fetchone()
                events = other.execute("SELECT count(*) FROM audit WHERE kind='release_dispatch_intent'").fetchone()[0]
                seen.append((row[0], events))
            finally: other.close()
            return {'receipt_id': 'done'}
        self.b._sinks['approved_sink'] = Sink('approved-example-audience', '1', check)
        p = self.proposal(approved=True)
        self.call('execute_release', {'proposal_id': p})
        self.assertEqual(seen, [('DISPATCHING', 1)])

    def test_audit_failure_before_dispatch_has_no_effect(self):
        p = self.proposal(approved=True)
        original = self.b.store.append
        def fail(*args, **kwargs): raise sqlite3.OperationalError('synthetic audit failure')
        self.b.store.append = fail
        try:
            r = self.call('execute_release', {'proposal_id': p})
            self.assertEqual(r['error'], 'integrity_or_storage_failure')
            self.assertEqual(self.deliveries, [])
            self.assertEqual(self.b.store.db.execute('SELECT state FROM proposals').fetchone()[0], 'APPROVED')
        finally: self.b.store.append = original

    def test_audit_failure_after_dispatch_reports_unknown_not_unsent(self):
        p = self.proposal(approved=True)
        original = self.b.store.append
        def fail_after(db, task, agent, kind, details):
            if kind == 'release_result': raise sqlite3.OperationalError('synthetic failure')
            return original(db, task, agent, kind, details)
        self.b.store.append = fail_after
        try:
            r = self.call('execute_release', {'proposal_id': p})
            self.assertEqual(r['error'], 'post_dispatch_audit_unavailable')
            self.assertEqual(r['delivery_outcome'], 'unknown')
            self.assertEqual(len(self.deliveries), 1)
            self.assertEqual(self.b.store.db.execute('SELECT state FROM proposals').fetchone()[0], 'DISPATCHING')
        finally: self.b.store.append = original


class Audit(Case):
    def test_clean_journal_verifies(self):
        self.call('context'); self.call('unsupported')
        self.assertGreater(self.b.store.verify()['seq'], 0)

    def test_append_only_triggers(self):
        with self.assertRaises(sqlite3.IntegrityError): self.b.store.db.execute('DELETE FROM audit')
        with self.assertRaises(sqlite3.IntegrityError): self.b.store.db.execute("UPDATE audit SET kind='changed'")

    def test_modified_journal_is_detected_and_blocks_actions(self):
        self.b.store.db.execute('DROP TRIGGER audit_no_update')
        self.b.store.db.execute("UPDATE audit SET kind='modified' WHERE seq=1")
        with self.assertRaises(IntegrityError): self.b.store.verify()
        self.assertEqual(self.call('context')['error'], 'integrity_or_storage_failure')

    def test_retained_external_head_detects_tail_truncation(self):
        self.call('context'); anchor = self.b.store.verify()
        self.b.store.db.execute('DROP TRIGGER audit_no_delete')
        self.b.store.db.execute('DELETE FROM audit WHERE seq=?', (anchor['seq'],))
        with self.assertRaises(IntegrityError): self.b.store.verify(anchor)

    def test_memory_head_detects_tail_truncation_without_external_file(self):
        self.call('context')
        self.b.store.db.execute('DROP TRIGGER audit_no_delete')
        self.b.store.db.execute('DELETE FROM audit WHERE seq=(SELECT max(seq) FROM audit)')
        self.assertEqual(self.call('context')['error'], 'integrity_or_storage_failure')

    def test_prior_external_anchor_allows_legitimate_later_events(self):
        anchor = self.b.store.verify(); self.artifact()
        self.assertGreater(self.b.store.verify(anchor)['seq'], anchor['seq'])

    def test_restart_requires_same_key(self):
        self.b.close()
        with self.assertRaises(IntegrityError): Broker(self.path, b'z'*32)
        self.b = Broker(self.path, KEY, clock=self.clock)

    def test_private_content_not_in_journal(self):
        secret = 'DEMO_PRIVATE_PAYLOAD_NEVER_A_REAL_SECRET'
        self.artifact(secret.encode())
        self.call('send_message', {'recipient': 'worker', 'text': secret})
        rows = str([dict(r) for r in self.b.store.db.execute('SELECT * FROM audit')])
        self.assertNotIn(secret, rows)
        self.assertNotIn(self.tokens['main'], rows)

class StartupAndDetachedApproval(Case):
    def test_startup_enforces_supplied_external_anchor(self):
        self.call('context')
        anchor = self.b.store.verify()
        self.b.store.db.execute('DROP TRIGGER audit_no_delete')
        self.b.store.db.execute('DELETE FROM audit WHERE seq=?', (anchor['seq'],))
        self.b.close()
        with self.assertRaises(IntegrityError): Broker(self.path, KEY, audit_anchor=anchor)
        # Restore a usable instance for cleanup; without an external anchor a valid
        # historical prefix is not distinguishable from legitimate old state.
        self.b = Broker(self.path, KEY, clock=self.clock)

    def test_separate_control_process_can_approve_without_a_live_sender(self):
        p = self.proposal()
        control = Broker(self.path, KEY, clock=self.clock)
        try:
            control.approve_release(p, reviewer='separate-reviewer')
        finally:
            control.close()
        self.assertEqual(self.call('execute_release', {'proposal_id': p})['result']['state'], 'DELIVERED')
        self.assertEqual(len(self.deliveries), 1)
