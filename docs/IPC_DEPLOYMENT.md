# Separate broker and runner

Use separate Linux accounts for the broker and the agent runner. The broker owns state and credentials; the runner gets a scoped token and connects through a Unix socket.

## Files and identities

| Resource | Owner and access |
|---|---|
| Broker state | Broker account; directory `0700` |
| Keys, configuration, database and session tokens | Broker account; files `0600` |
| Runner token | Runner account; one provisioned task token in a `0600` file |
| Runner checkpoints | Runner account; directory `0700` |
| Socket directory | Broker account; protected absolute path, typically `0750` with a shared group |
| Socket | `0600` by default, or `0660` with `--group-access` |

Protect socket parent directories from runner and group writes. Set group ownership and inheritance so the runner can reach the socket. The broker checks the peer's numeric UID and task token; the client checks the broker UID through Linux `SO_PEERCRED`.

Provision the required token from `STATE/sessions/AGENT.token` into the runner's private token file using your administrator channel. Keep token values out of commands and prompts. Protect service units, environment files and executable paths with the same ownership rules.

## Start the broker

Create the task using the [deployment guide](../CUSTOMER_DEPLOYMENT.md), then run under the broker account:

```sh
agent-effect-gate serve-unix --state /var/lib/aeg/state \
  --socket /run/aeg/gate.sock --allow-uid FRAMEWORK_UID \
  --group-access --max-workers 16 \
  --anchor /var/lib/aeg-anchors/current.json --production --check-sandbox
```

Set `FRAMEWORK_UID` to the runner's numeric UID. Repeat `--allow-uid` for additional permitted runner accounts. The server holds the state lease for its lifetime, bounds request sizes and concurrency, and exposes task-scoped agent operations.

Connect with [GateClient or a framework adapter](FRAMEWORKS.md), or start the scoped stdio MCP bridge under the runner account:

```sh
agent-effect-gate-mcp --socket /run/aeg/gate.sock \
  --token-file /private/runner/main.token --broker-uid BROKER_UID
```

Set `BROKER_UID` to the broker's numeric UID. Framework SDKs belong in the runner environment.

## Run a model

Create the private checkpoint directory under the runner account and inject the approved provider credential through your secret manager:

```sh
agent-effect-gate model-client --socket /run/aeg/gate.sock \
  --token-file /private/runner/main.token --broker-uid BROKER_UID \
  --model YOUR_ENABLED_MODEL_ID --prompt-file /private/runner/task.txt \
  --allow-provider-egress --checkpoint /private/runner/runs/task.json \
  --max-steps 20 --max-output-tokens 4096
```

After an exact approval, repeat the same command with `--resume`. Exit codes are `0` for completion, `4` for pause, `3` for runtime failure and `2` for configuration failure.

Task quotas persist across invocations. Context and answer reads use the read budget. A saved pending request retains its action reservation and remains subject to the current policy and retry allowance. Preserve the checkpoint and request ID during uncertain-outcome recovery.

## Review and administration

Run the review console or CLI under the trusted broker account:

```sh
agent-effect-gate review-tool --state /var/lib/aeg/state --call CALL_ID
agent-effect-gate approve-tool --state /var/lib/aeg/state --call CALL_ID \
  --reviewer PROVISIONED_REVIEWER
```

Inspect the exact request before approval. The CLI authenticates the reviewer with a prompted password or a private `--password-file`. Accounts have explicit task scope. `--break-glass` is an operator override recorded separately in the audit log.

## Shutdown and maintenance

Use `SIGTERM` to drain the server. It preserves an existing socket path; after a crash, confirm that its process has stopped before removing a stale socket. Client transport failures require explicit recovery, and cancelling an async wait leaves an already-sent effect in progress.

Stop or fence dispatchers on every host before backup or maintenance. Backups include `STATE/runs/*.json`; checkpoint files stored under the runner account need a coordinated backup. Protect both with your encrypted-storage and retention policy.

Restore suspends tasks and revokes pending approvals. Follow [recovery](RECOVERY.md) to reconcile outcomes, review credentials and resume. Monitor action/read/retry capacity, prepared-request storage, database and WAL growth, pending approvals, uncertain calls and retained audit heads.
