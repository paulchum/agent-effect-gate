# Design and trust model

The gate separates four roles: the agent proposes, the policy sets permission, a reviewer approves when required, and the broker executes. The audit log records each transition.

## Request lifecycle

Every JSONL, MCP, framework and Unix-client operation enters the broker's task and policy checks. Agent credentials identify a task and agent. Policy changes, reviewer accounts, approvals and maintenance remain operator-side operations.

A prepared request binds its arguments, payload, policy and adapter configuration. Approval covers that stored request. Immediately before dispatch, the executor checks the current policy and private adapter and credential bindings.

The broker records `DISPATCHING` before invoking a tool. A known result becomes `SUCCEEDED` or `FAILED`. An ambiguous outcome becomes `UNKNOWN` and pauses execution for reconciliation. Replays preserve the original request identity and return the recorded state. Destination receipts establish the external outcome during recovery.

## Budgets and saved runs

Task-wide action, read and retry counters persist in state. An already-reserved pending action can resume within its remaining retry allowance. New model steps require action capacity. Status polls and external context reads use the read budget; trusted in-process display snapshots use a separate host interface.

Checkpoints preserve the exact pending request and connector state. They are size-limited, written atomically, protected by a whole-run lock and bound to the broker, task and agent. The broker checks permission again when a saved request resumes.

Task budgets bound agent activity. Operators set host storage quotas, retention, service resource limits and monitoring for the deployment as a whole.

## Trusted components

| Component | Responsibility |
|---|---|
| Broker and adapters | Validate requests, bind approvals, protect credentials and record execution |
| Reviewer and operator interfaces | Authenticate people, enforce task scope and record control actions |
| Host and administrators | Protect accounts, files, executables, mapping helpers and the kernel |
| Rootfs builder | Select the binaries and libraries available to sandboxed code |
| Audit-head storage | Retain verified history anchors under separate control |
| Runner host | Expose the gate's tools and apply the approved provider-egress policy |

Distinct broker, runner and worker identities give each process a separate filesystem and credential scope. User namespaces, a syscall allowlist and resource limits constrain sandboxed code. Test those controls on the service account, kernel and rootfs used for deployment.

Model-provider traffic is a separately authorized channel. The built-in connector submits one structured broker action per step, and the answer gate checks citations against captured output. Operators review answer content and control any additional tools, plugins or network channels in the surrounding application.

## Audit and recovery

The HMAC chain authenticates local history relative to protected keys and independent anchors. Bundle checksums identify exact file contents. Publisher identity and software provenance are handled by the distribution channel.

A backup captures transaction-consistent state and default local checkpoints under a state lease. Restore suspends tasks, revokes pending approvals and ends reviewer sessions. Operators review retained agent credentials and external checkpoints before resumption.

`reconcile` records an independently verified terminal outcome for an uncertain tool call or release. It requires a suspended task and records the operator, state transition and evidence-reference digest. It updates the record without dispatching the effect; the original receipt stays in the operator's evidence store.

## Verification

[Validation](VALIDATION.md) separates local test results from checks on the deployment host. Use [deployment](CUSTOMER_DEPLOYMENT.md) for service setup and [recovery](docs/RECOVERY.md) for backup, reconciliation and restored-state checks.
