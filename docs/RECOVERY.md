# Backup and recovery

Keep broker state private and retain verified audit heads under separate control. Before backup, upgrade or reconciliation, stop or fence every process that can dispatch from that state, including runners on other hosts.

## Protect state and audit heads

State contains the broker key, task policies, agent sessions, prepared requests, observations, reviewer accounts and audit history. Default checkpoints live in `STATE/runs`.

Use the broker account to control access. State, checkpoints and backups contain plaintext secrets and task data; store them under your encryption and retention policy. Keep audit heads separately so a restored journal can be checked against previously recorded history.

## Back up

Stop dispatchers on every host, then verify and back up the state:

```sh
agent-effect-gate audit --state STATE --anchor INDEPENDENT_ANCHOR
agent-effect-gate backup --state STATE --destination NEW_BACKUP \
  --anchor INDEPENDENT_ANCHOR
```

Retain the verified audit head in your independent store. The backup command holds a state lease and writes an authenticated inventory of file hashes. It includes default checkpoints under `STATE/runs`. Back up checkpoints stored elsewhere in coordination with the broker backup.

The lease coordinates local processes. Use your service supervisor or deployment controls to fence dispatchers on other machines.

## Restore

Restore into a new directory:

```sh
agent-effect-gate restore --backup BACKUP --state NEW_STATE \
  --anchor INDEPENDENT_ANCHOR --operator OPERATOR_NAME
```

Restore checks ownership, the file inventory, hashes, audit authentication and anchor consistency. It suspends tasks, revokes pending tool and release approvals, and invalidates reviewer sessions. Agent credentials remain in the restored state; review or reissue them before resuming. Checkpoint lock sidecars are recreated as needed.

Use destination receipts or service logs to establish the outcomes of pending or uncertain calls. Preserve their original request IDs and checkpoint bindings throughout recovery. Confirm policy, tool configuration, account scope and the latest retained audit head before resumption.

## Reconcile an uncertain effect

Reconciliation records a verified outcome without sending the action again.

Stop or fence every dispatcher, suspend the task and retain a verified audit head. Establish the outcome from destination records, receipts or an idempotency log. A timeout leaves delivery uncertain until that evidence resolves it.

For a confirmed successful tool call:

```sh
agent-effect-gate suspend --state STATE --task TASK --operator OPERATOR
agent-effect-gate audit --state STATE --anchor INDEPENDENT_ANCHOR
agent-effect-gate reconcile --state STATE --anchor INDEPENDENT_ANCHOR \
  --kind tool --id CALL_ID --outcome succeeded --operator OPERATOR \
  --evidence-reference INCIDENT_OR_RECEIPT_REFERENCE
```

Use `--outcome failed` for a verified failure, or `--kind release` for a legacy release proposal. Eligible records are `UNKNOWN` or interrupted `DISPATCHING` calls on suspended tasks.

| Verified outcome | Tool state | Release state |
|---|---|---|
| `succeeded` | `SUCCEEDED` | `DELIVERED` |
| `failed` | `FAILED` | `FAILED` |

The CLI takes an exclusive state lease and records the operator, old and new states, and SHA-256 of the evidence reference. Keep the underlying receipt in your evidence store. The command changes the terminal status; stored observations remain as originally captured. Reconciled calls stay terminal on later polls.

After resolving uncertain records, check policy, credentials and checkpoint bindings, then resume:

```sh
agent-effect-gate resume --state STATE --task TASK --operator OPERATOR
agent-effect-gate doctor --state STATE --anchor INDEPENDENT_ANCHOR \
  --production --check-sandbox
```

Restart dispatchers after readiness succeeds. Python control-plane callers must provide the same all-host fencing as the CLI procedure.

### Read failures

Trusted `network_read` exceptions produce sanitized `FAILED` results. Use destination logs to establish whether the request arrived. Write or code calls with ambiguous outcomes remain `UNKNOWN` for reconciliation. Recovery preserves the existing request identity and uses explicit retry decisions.

## Upgrade

Stop dispatchers, retain an independent audit head and take a protected backup. Install into a new environment and perform the first state open while execution is stopped. Retain the old installation and backup together for recovery.

This build normalizes legacy response caches in one transaction. It keeps request IDs, hashes, canonical observations, quota usage, task suspensions and signed audit history, and removes duplicate cached observations. The migration is idempotent and records changes in the journal. Existing uncertain outcomes stay available for operator reconciliation.

The sandbox's identity and syscall configuration changes its approval binding. Create and review new code proposals after upgrading it. Run the delegated-ID sandbox checks under the production service account before resuming code execution.

## Maintenance and contention

Startup verifies the journal in a read snapshot, then briefly takes a writer transaction to authenticate newly appended events and apply migrations. Pre-dispatch contention returns retryable `broker_busy`. Contention after possible execution returns an uncertain outcome for reconciliation. Integrity failures stop execution.

Run `compact` while dispatchers are stopped to reclaim freed SQLite pages:

```sh
agent-effect-gate compact --state STATE --anchor INDEPENDENT_ANCHOR
```

Keep secret rotation, audit-head retention, storage monitoring and restore drills in the regular operating schedule. Validate state compatibility with the exact application used for restore or upgrade.
