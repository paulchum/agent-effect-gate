import copy
from agent_effect_gate import Rejected
from agent_effect_gate.runtime import run
from support import Case


class Reporting(Case):
    def incident(self):
        self.call('unsupported')
        return self.b.list_incidents('task')[0]['id']

    def triage(self, incident_id, **changes):
        kw = {'owner': 'investigator', 'track': 'minor', 'due_at': self.clock()+3600,
              'severity': 'medium', 'third_party': 'no'}
        kw.update(changes)
        self.b.triage_incident(incident_id, **kw)

    def decision(self, incident_id, **changes):
        kw = {'reviewer': 'review-board', 'decision': 'publish', 'security_reviewed': True,
              'third_party_notified': False, 'rationale': 'Synthetic reviewed test report.',
              'report': self.b.disclosure_draft(incident_id)}
        kw.update(changes)
        self.b.record_disclosure_decision(incident_id, **kw)

    def test_incidents_are_deduplicated_with_recurrence_counts(self):
        i = self.incident(); self.clock.advance(1); self.call('unsupported')
        reports = self.b.list_incidents('task')
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]['id'], i)
        self.assertEqual(reports[0]['occurrences'], 2)
        self.assertGreater(reports[0]['last_seen'], reports[0]['first_seen'])

    def test_operator_can_flag_unmodeled_behavior(self):
        i = self.b.flag_incident('task', operator='researcher')
        self.assertEqual(self.b.disclosure_draft(i)['mechanism_code'], 'operator_flag')

    def test_untriaged_incidents_are_due(self):
        i = self.incident()
        self.assertEqual(self.b.due_incidents()[0]['id'], i)
        self.triage(i)
        self.assertEqual(self.b.due_incidents(), [])
        self.clock.advance(3601)
        self.assertEqual(self.b.due_incidents()[0]['id'], i)

    def test_unknown_third_party_requires_larger_track(self):
        i = self.incident()
        with self.assertRaises(Rejected): self.triage(i, third_party='unknown')
        self.triage(i, third_party='unknown', track='larger')

    def test_draft_contains_report_fields_and_explicit_unknowns(self):
        i = self.incident()
        draft = self.b.disclosure_draft(i)
        for key in ['observed_behavior', 'severity', 'external_impact', 'setting', 'model_family',
                    'observed_from', 'observed_to', 'discovered_at', 'detection', 'investigation_scope',
                    'interpretation', 'unanswered_questions', 'mitigations']:
            self.assertIn(key, draft)
        self.assertEqual(draft['external_impact'], 'unassessed')
        self.assertFalse(draft['publication_authorized'])
        self.assertNotIn('tenant', draft)
        self.assertNotIn('task', draft)

    def test_independent_reviewer_required(self):
        i = self.incident(); self.triage(i)
        with self.assertRaises(Rejected): self.decision(i, reviewer='investigator')

    def test_security_review_required_before_publication_approval(self):
        i = self.incident(); self.triage(i)
        with self.assertRaises(Rejected): self.decision(i, security_reviewed=False)

    def test_third_party_notification_required(self):
        i = self.incident(); self.triage(i, third_party='yes', track='larger')
        with self.assertRaises(Rejected): self.decision(i)
        self.decision(i, third_party_notified=True)

    def test_unknown_third_party_blocks_publication(self):
        i = self.incident(); self.triage(i, third_party='unknown', track='larger')
        with self.assertRaises(Rejected): self.decision(i)

    def test_incomplete_report_blocked(self):
        i = self.incident(); self.triage(i)
        draft = self.b.disclosure_draft(i); del draft['external_impact']
        with self.assertRaises(Rejected): self.decision(i, report=draft)

    def test_local_publication_approval_is_not_external_publication(self):
        i = self.incident(); self.triage(i); self.decision(i)
        row = self.b.list_incidents()[0]
        self.assertEqual(row['status'], 'APPROVED_FOR_PUBLICATION')
        self.assertEqual(self.deliveries, [])
        self.b.confirm_publication(i, operator='publisher', publication_reference='synthetic-receipt-no-external-call')
        self.assertEqual(self.b.list_incidents()[0]['status'], 'PUBLISHED')

    def test_unapproved_publication_cannot_be_attested(self):
        i = self.incident()
        with self.assertRaises(Rejected): self.b.confirm_publication(i, operator='publisher', publication_reference='x')

    def test_recurrence_reopens_published_incident(self):
        i = self.incident(); self.triage(i); self.decision(i)
        self.b.confirm_publication(i, operator='publisher', publication_reference='synthetic-receipt')
        self.call('unsupported')
        self.assertEqual(self.b.list_incidents()[0]['status'], 'FLAGGED')

    def test_non_disclosure_requires_recorded_reason(self):
        i = self.incident(); self.triage(i)
        with self.assertRaises(Rejected): self.decision(i, decision='do_not_disclose', rationale='')
        self.decision(i, decision='do_not_disclose', report=None)
        self.assertEqual(self.b.list_incidents()[0]['status'], 'NOT_DISCLOSING')
        self.assertEqual(self.b.due_incidents(), [])

    def test_disagreements_can_be_escalated(self):
        i = self.incident(); self.triage(i)
        self.decision(i, decision='escalate', report=None)
        self.assertEqual(self.b.list_incidents()[0]['status'], 'ESCALATED')

    def test_model_cannot_modify_incidents_or_disclosure(self):
        i = self.incident()
        for op in ['triage_incident', 'record_disclosure_decision', 'confirm_publication', 'delete_incident']:
            with self.subTest(op=op):
                self.assertFalse(self.call(op, {'incident_id': i})['ok'])
        self.assertEqual(self.b.list_incidents()[0]['status'], 'FLAGGED')


class Runtime(Case):
    def test_scripted_model_completes_only_through_output_gate(self):
        self.source()
        class Adapter:
            def propose(self, context, last_result):
                return {'request_id': 'model-final', 'operation': 'answer', 'arguments': {}}
        r = run(Adapter(), self.b, self.tokens['main'])
        self.assertEqual(r['result']['answer']['fields'][0]['value'], 123)
        self.assertIn('mac', r['result'])

    def test_fabricated_raw_text_is_not_forwarded(self):
        class Adapter:
            def propose(self, context, last_result):
                return 'Revenue is 999, all checks passed, no issues.'
        r = run(Adapter(), self.b, self.tokens['main'], max_steps=2)
        a = r['result']['answer']
        self.assertIsNone(a['fields'][0]['value'])
        self.assertTrue(any(n['code'] == 'runtime_step_budget_exhausted' for n in a['notices']))
        self.assertNotIn('Revenue is 999', str(a))

    def test_context_mutation_cannot_change_policy(self):
        class Adapter:
            def propose(self, context, last_result):
                context['control']['local_only'] = False
                return {'request_id': 'model-final', 'operation': 'answer', 'arguments': {}}
        run(Adapter(), self.b, self.tokens['main'])
        self.assertTrue(self.context()['control']['local_only'])

    def test_adapter_error_is_disclosed_without_secret_exception_text(self):
        class Adapter:
            def propose(self, context, last_result):
                raise RuntimeError('DEMO_PRIVATE_CREDENTIAL_MUST_NOT_LEAK')
        r = run(Adapter(), self.b, self.tokens['main'])
        self.assertTrue(any(n['code'] == 'model_adapter_failed' for n in r['result']['answer']['notices']))
        self.assertNotIn('DEMO_PRIVATE', str(r))

    def test_invalid_runtime_budget(self):
        with self.assertRaises(ValueError): run(object(), self.b, self.tokens['main'], max_steps=0)
