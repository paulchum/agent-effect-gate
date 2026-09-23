# Changes and upgrade notes

Historical notes from the supplied pre-publication bundle. The test counts below describe that earlier revision; current public release validation is documented in [VALIDATION.md](VALIDATION.md).

The supplied revision repaired request handling, sandbox isolation, startup verification and the review workflow. Its original distribution included source, the executable, regression tests, test evidence and deployment guides. The public release retains the implementation and repair notes, with versioning and distribution changes listed in [CHANGELOG.md](CHANGELOG.md). Historical evidence is excluded from public assets.

## Changes

| Area | Behavior |
|---|---|
| Read failures | Trusted `network_read` failures finish as sanitized `FAILED` results. Ambiguous write and code outcomes remain `UNKNOWN` for operator reconciliation. |
| Reconciliation | The operator-only `reconcile` command records a verified outcome for a suspended task under an exclusive state lease. It updates the record without redispatching. |
| Startup | Journal verification uses a WAL read snapshot, followed by a brief writer transaction for appended events and migrations. Pre-dispatch database contention returns retryable `broker_busy`. |
| Sandbox | Code uses a separate worker identity. Non-root brokers use delegated subordinate UID/GID mappings and trusted mapping helpers. Setup clears groups and drops privileges before code starts; seccomp uses a restricted allowlist. |
| Citation and ID corrections | Invalid requests are rejected and quota-limited. Citation mismatches and request-ID conflicts leave the security-denial breaker unchanged; authorization denials still count toward it. |
| Status polling | Polls use the read budget and store bounded request hashes. Observations stay in their canonical records. A transactional migration removes legacy cached copies. |
| Reviewer credentials | Review uses stored plans and reviewer accounts. Tool credentials stay with the executor, which checks adapter and credential bindings before dispatch. |
| Upload preview | Reviewers see inert UTF-8 text for valid text payloads, media type, byte count, SHA-256 and exact base64. Binary payloads retain their exact bytes. |
| Approval renewal | Reviewers can renew expired approvals while the request and bindings remain current. Revoked, dispatched and changed requests retain their existing state. |
| Runtime pauses | An uncertain post-dispatch outcome pauses the runner and preserves the request identity for reconciliation. |

## Regression coverage

The repair run passed **479 tests**, including **32 new regressions** and **16 real sandbox tests**. All 447 original test names remain. Four HTTP read-failure tests now expect `FAILED`; they retain their certificate, timeout and single-invocation checks. Distribution tests cover all 41 application assets.

The supplied 8,000-input check completed with zero unexpected exceptions or broker stops. In the 300-poll reproduction, response-cache contents fell from **36,221,065 to 265 bytes**, and action usage fell from **302 to 2**. These figures measure cached response contents and action counters.

A 350,001-row journal accepted 50 concurrent writes during startup verification. Maximum measured write latency was 0.1178 seconds, and the final authenticated heads matched. Three installed workflows passed 35 checks covering recovery, Unix clients, checkpoints, built-in MCP and reviewer HTTP. Chromium component checks covered upload previews and approval renewal.

[Validation](VALIDATION.md) records the test environments, retained evidence and checks to run on the deployment host.

## Upgrade existing state

Stop or fence dispatchers on every host. Retain a verified audit head independently and take a protected backup. Install into a new environment and perform the initial state open while dispatchers are stopped.

Cache normalization runs transactionally and preserves quotas, suspensions, canonical observations and audit history. Run `compact` while dispatchers are stopped to reclaim freed database pages. Existing uncertain calls remain available for reconciliation.

### Sandbox setup

Provision subordinate UID/GID ranges for the broker account and install the distribution's trusted `newuidmap` and `newgidmap` helpers. Explicit worker IDs must belong to those ranges and differ from the broker identity. Use a dedicated non-root service account and protect the rootfs and helper paths.

The sandbox manifest changes approval bindings. Create and review new exact code proposals under the updated configuration. Run the actual sandbox suite and `doctor --production --check-sandbox` under the service account before enabling code execution.

### Reviewer setup

Keep tool credentials in the executor environment. Give the reviewer process its protected state access and authenticated reviewer accounts. Check executor readiness separately so the console remains available for suspended tasks and uncertain calls.

## Resolve uncertain calls

Follow [recovery](docs/RECOVERY.md#reconcile-an-uncertain-effect) to suspend the task, verify the destination outcome and record it with `reconcile`. Keep the receipt separately and use its reference in the command. Resume after checking policy, credentials, checkpoints and readiness.

## Build identity

The executable remains byte-for-byte identical to the repaired build:

```text
613caa554ebea74a10a5bbf94f621430ec709f1f7565e9a6b6acc37dfb0b5286
```

`MANIFEST.json` records the current file inventory and checksums. [Validation](VALIDATION.md#evidence-and-build-identity) links the current checks and original repair evidence.

The original repair patch applies to a clean extraction of the original project:

```sh
git apply --check /path/to/agent-effect-gate-fixes.patch
git apply /path/to/agent-effect-gate-fixes.patch
python3 scripts/build_release.py
```

That patch contains source, tests and the original repair documentation. The documentation patch supplied with this revision applies to the fixed project and updates Markdown files. Each patch excludes generated distribution files; `scripts/package.py` rebuilds the source archive and manifest after evidence has been refreshed. The complete ZIP includes those outputs.
