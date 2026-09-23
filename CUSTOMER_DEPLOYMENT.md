# Deployment

This guide sets up scoped HTTPS reads, sandboxed Python or shell, and a reviewer account. Run the broker under a dedicated non-root Linux account and the agent under a separate runner account.

## Install and prepare accounts

Follow [installation](docs/DEPLOYMENT.md) to install the application into the broker's virtual environment. Add Uvicorn there for the review console. Install framework SDKs in the runner's environment.

Give the broker a private state directory and the runner its own task token and checkpoint directory. Select a separately controlled location for audit heads. The [process-separation guide](docs/IPC_DEPLOYMENT.md) covers ownership, permissions and socket setup.

## Prepare the sandbox

Have a host administrator assign non-overlapping subordinate UID and GID ranges to the broker account in `/etc/subuid` and `/etc/subgid`. Install the distribution's trusted `newuidmap` and `newgidmap` helpers, util-linux and libseccomp, and enable unprivileged user namespaces.

The sandbox selects a worker UID/GID from those ranges. Explicit `worker_uid` and `worker_gid` settings must also fall within the delegated ranges and differ from the broker identity. Trusted setup runs as namespace UID 0, clears supplementary groups, then drops to the worker identity before starting code.

Protect the mapping helpers with administrator ownership. Keep the application, rootfs and their parent paths protected from runner and worker writes. Confirm that the host or container permits the required identity mappings and nested namespaces.

## Create a task

Under the broker account:

```sh
umask 077
agent-effect-gate build-rootfs --destination "$HOME/aeg-rootfs"
mkdir -p "$HOME/aeg-anchors"
agent-effect-gate setup --state "$HOME/aeg-state" \
  --rootfs "$HOME/aeg-rootfs" --reviewer alice --require-code-approval \
  > "$HOME/aeg-anchors/initial.json"
agent-effect-gate doctor --state "$HOME/aeg-state" \
  --anchor "$HOME/aeg-anchors/initial.json" --production --check-sandbox
```

Setup prompts for a reviewer password. For unattended setup, use `--password-file` with a private, operator-owned file.

The generated profile allows HTTPS reads from the configured Python documentation path and grants sandboxed code execution. `--require-code-approval` makes each code job wait for review. Omit that flag to grant bounded standing code permission. External writes always require exact approval.

Use `--task-id` and `--tenant-id` to name the task and tenant. For a custom configuration, edit the profile and run `validate-config` followed by `init`. The [deployment examples guide](deploy/README.md) describes the supplied profiles.

Retain the initial audit head separately, and continue retaining verified heads as the task runs. Run the real sandbox suite with `AEG_TEST_ROOTFS` set to the selected rootfs under the service account.

## Start the review console

```sh
agent-effect-gate review --state "$HOME/aeg-state" \
  --anchor "$HOME/aeg-anchors/initial.json" --production
```

The default listener is `127.0.0.1:8765`. For remote reviewers, configure HTTPS and pass the exact browser origin through `--public-origin`. [review-proxy.conf](deploy/review-proxy.conf) shows a reverse-proxy configuration.

Reviewers see the destination, arguments, code and payload of each pending request. Uploads show media type, byte count, SHA-256, exact base64 and an inert UTF-8 preview for valid text. Binary payloads retain their exact bytes. Expired approvals return to the pending queue and can be renewed while the request remains current and undispatched; revocation is final.

The review process uses stored plans and reviewer accounts. Keep tool API credentials in the executor environment. The executor checks current adapter and credential bindings immediately before dispatch. Run executor readiness separately so reviewers can continue inspecting suspended tasks and uncertain calls.

Manage reviewer scope with:

```sh
agent-effect-gate reviewer-add --state "$HOME/aeg-state" \
  --username bob --task customer-task
agent-effect-gate reviewer-disable --state "$HOME/aeg-state" --username bob
```

Repeat `--task` when granting an account access to several tasks. Approval authorizes a request; the agent's execution step runs it.

## Connect an agent

For a separate runner account, start `serve-unix` and provision a private token. Connect with `GateClient`, a framework adapter or the scoped `agent-effect-gate-mcp` bridge. See [process separation](docs/IPC_DEPLOYMENT.md) and [frameworks](docs/FRAMEWORKS.md).

The state-owning `agent-effect-gate mcp --state STATE --agent main` command belongs in the trusted broker process. Both built-in MCP paths expose 15 agent operations.

## Run a model and resume after approval

Select a model available in your provider account and supply its credential through the executor's protected environment:

```sh
agent-effect-gate model-run --state "$HOME/aeg-state" \
  --model OPERATOR_SELECTED_MODEL --prompt-file deploy/example-task.txt \
  --allow-provider-egress --max-steps 20 \
  --anchor "$HOME/aeg-anchors/initial.json" --production --check-sandbox
```

`--allow-provider-egress` authorizes sending the prompt, task context and results to the provider. `--credential-env` selects the credential environment variable; its default is `OPENAI_API_KEY`.

The default checkpoint is `STATE/runs/AGENT.json`. After approving the pending request, repeat the same command with `--resume`. Use a separate protected checkpoint for a new conversation. Task budgets persist across invocations.

For a separate runner, `model-client` provides the same checkpoint flow over the Unix socket. Exit codes are `0` for completion, `4` for pause, `3` for runtime failure and `2` for configuration failure. Keep an uncertain call's checkpoint and request ID while the operator follows [reconciliation](docs/RECOVERY.md#reconcile-an-uncertain-effect).

## Before serving workloads

Check the complete path on the deployment host: service identities, subordinate-ID sandbox launch, rootfs, tool credentials and destinations, selected framework SDKs, MCP host and model provider.

For the review console, exercise HTTPS login, account scope, approval, expiry, logout, Origin checks, CSRF protection and cookies in the browser reviewers will use. Set storage and service limits, monitor budgets and uncertain calls, and run a backup, restore and reconciliation drill using independently retained audit heads.

[Validation](VALIDATION.md) records the supplied test results. [Recovery](docs/RECOVERY.md) and [incident reporting](docs/REPORTING.md) cover ongoing operations.
