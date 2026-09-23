# Incident reports

The gate records events that need investigation and helps operators prepare reviewed reports. Investigators determine the cause, impact and response from the event and its supporting evidence.

## Detection

Rejected requests, missing source bindings, uncertain dispatches, runtime failures and operator flags can create an incident candidate. Records are grouped by mechanism code and task, with first and latest timestamps, journal event references, occurrence count and review status.

An event can reflect missing input, a mistaken call or a policy violation. Establish which occurred during investigation.

A new occurrence after `PUBLISHED`, `NOT_DISCLOSING` or `APPROVED_FOR_PUBLICATION` reopens the record as `FLAGGED`. The current record shows the latest state; the journal preserves decision hashes and event history. Archive each reviewed report body by its journaled hash in your records system.

## Triage

```text
FLAGGED -> INVESTIGATING -> APPROVED_FOR_PUBLICATION -> PUBLISHED
                       \-> NOT_DISCLOSING
                       \-> ESCALATED

New occurrence after a completed decision -> FLAGGED
```

`triage_incident()` requires an owner, track, future deadline, severity and third-party assessment. Choose the `ready`, `minor` or `larger` track. The default workflow uses `larger` when third parties are affected or their status is still unknown.

Publication approval requires security review, a reviewer other than the investigation owner, and a resolved third-party assessment. For affected third parties, record notification before approval. Authenticate operators and reviewers through the host control interface, and use their verified identities in incident decisions.

`due_incidents()` returns untriaged and overdue open records. Call it from your scheduler to drive reminders and escalation.

## Draft a report

`disclosure_draft(incident_id)` returns redacted JSON covering the observed behavior, mechanism, severity, external impact, lifecycle setting, model family, observation interval, discovery time, recurrence, detection method, investigation scope, interpretation, open questions, mitigations, track and review status.

Unestablished fields remain marked for investigation. The default draft omits task and tenant IDs, credentials, message contents and artifact payloads. Check the operator-supplied model-family label before disclosure.

`record_disclosure_decision()` validates the report fields and records the reviewer, decision, rationale and review flags. The journal stores hashes of the rationale and reviewed report; their private text remains in protected state. `do_not_disclose` requires a rationale, and `escalate` records unresolved disagreement for your organization's review process.

## Approve and publish

A `publish` decision moves the report to `APPROVED_FOR_PUBLICATION`. Publish through your organization's disclosure system, then call `confirm_publication()` with the resulting reference. The gate records that operator-attested reference and marks the report `PUBLISHED`.

Approval, external publication and confirmation are separate steps. Keep the published document and its receipt in your records system.

## CLI examples

```sh
agent-effect-gate incidents --state "$STATE" --task TASK
agent-effect-gate report --state "$STATE" --incident INC_ID
agent-effect-gate triage --state "$STATE" --incident INC_ID \
  --owner investigator --track larger --severity unassessed \
  --third-party unknown --due-at UNIX_TIMESTAMP
```

Set the task and incident IDs to the records under investigation, and choose a future Unix timestamp for the deadline. Keep full transcripts and source captures in an access-controlled evidence store with a retention policy. The audit journal records bounded event details and hashes rather than raw model transcripts.
