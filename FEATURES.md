# Features

Agent Effect Gate checks tool calls, manages exact approvals, runs tools and records the results. This page covers the interfaces and behavior behind the [README](README.md).

## Tasks and permissions

Each request carries a task-scoped agent credential. The task policy controls tool access, approval requirements, release destinations, collaboration channels and budgets. Operators create and change policies; reviewers approve individual requests.

Artifacts belong to a task. Agents read, share and message through the relationships allowed by its policy. Evidence fields resolve against captured sources, and answer citations must quote stored observations exactly. Answer envelopes include provenance, limitations supplied with the answer and notices from the gate.

## Agent interfaces

The built-in MCP server and model runner expose 15 operations:

| Group | Operations |
|---|---|
| Task and discovery | `context`, `answer`, `inbox`, `list_tools`, `resolve_field` |
| Artifacts and messages | `put_artifact`, `read_artifact`, `share_artifact`, `send_message` |
| Releases | `propose_release`, `execute_release` |
| Tools and answers | `propose_tool`, `execute_tool`, `read_observation`, `submit_answer` |

Framework adapters expose 11 typed functions. `aeg_call_tool` combines proposal and execution; `aeg_execute_tool` resumes a call after approval. The remaining functions cover discovery, context, observations, artifacts, sharing, messages and answers. `ToolBundle.assert_inventory()` checks the registered tool objects and count.

`GateClient` provides synchronous and asynchronous calls over an authenticated Unix socket. Both sides check the other process's Linux UID. The socket carries agent operations; reviewer and admin commands use the separate control interface.

See [frameworks and MCP](docs/FRAMEWORKS.md) for examples.

## Tools

| Tool | Operator configuration | Agent input |
|---|---|---|
| HTTPS read | Site, path prefix, query keys, response size and timeout | Path and permitted query values |
| HTTPS upload | Endpoint, credentials and payload limits; exact approval required | Payload and permitted request arguments |
| GitHub code search | Named repositories, credentials and result limits | Search arguments |
| Python or shell | Root filesystem, worker identity and resource limits | Code, artifact inputs and output filenames |

Code jobs run in fresh Linux namespaces with a read-only root filesystem, a temporary workspace, a restricted environment and a syscall allowlist. Inputs and outputs pass through bounded artifact handling.

Custom tools implement `ToolAdapter` in [tool_types.py](agent_effect_gate/tool_types.py): `manifest()` describes the tool, `prepare()` validates and freezes its arguments, and `invoke()` makes one bounded execution attempt. Keep preparation free of external effects and store credentials in the operator-owned adapter.

## Approvals and review

Reviewers sign in with task-scoped accounts. The console shows the frozen destination, arguments, code and payload before approval, rejection or revocation. Upload previews include UTF-8 text where applicable, media type, byte count, SHA-256 and exact base64.

Approvals expire after five minutes by default. An expired approval can be renewed while its request and bindings remain current. Revocation is final. A policy, adapter or credential change requires a new matching approval.

Approval authorizes the stored request. Execution is a separate agent step. The reviewer process reads stored plans; the executor holds tool credentials and checks their bindings before dispatch. Operator overrides are explicit and separately audited.

## Requests, budgets and recovery

A logical request ID identifies one request across reconnects. Reusing it with changed arguments returns a conflict. Replaying a completed request returns its result, and status polls use the read budget. Read receipts store bounded hashes while observations remain in their canonical records.

Action, read and retry budgets persist across runs. Policies also cap calls per tool and the total size of prepared requests. Repeated authorization denials suspend a task; citation corrections and request-ID conflicts remain quota-limited without increasing that breaker.

The model runner saves its pending request before dispatch. Checkpoints use private, atomic files bound to the task, broker and connector configuration. After approval, `--resume` continues the saved request. Completed checkpoints return the saved result. Uncertain outcomes pause for operator reconciliation.

## Operations

The CLI provides task setup, configuration validation, readiness checks, reviewer accounts, JSONL/MCP/Unix serving, model runs, audit inspection, incident triage, suspension, reconciliation, compaction, backup and restore.

Backups include the default run checkpoints. Restore creates suspended tasks, revokes pending approvals and ends reviewer sessions. Operators reconcile outcomes and review agent credentials before resuming. See [recovery](docs/RECOVERY.md).

Tests cover broker permissions, request replay, real sandbox execution, installed workflows, reviewer HTTP and UI behavior, storage limits and distribution integrity. [Validation](VALIDATION.md) records the results and deployment checks.
