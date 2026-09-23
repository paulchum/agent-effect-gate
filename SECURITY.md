# Security

Route every agent tool call through the gate. Run the broker, agent runner and sandbox worker under separate Linux identities. Keep operator and reviewer access on the trusted side of that separation.

## Accounts and files

The broker account owns task state, the signing key, tool credentials and adapter configuration. The runner receives its task token and a private checkpoint directory. The sandbox worker receives the selected code and artifact inputs.

Use mode `0700` for private state and checkpoint directories and `0600` for keys, tokens and configuration files. Protect their parent directories, service units, environment files, executables and root filesystem from runner or worker writes. Root administrators and processes running as the broker account share the broker's trust boundary.

The Unix connection checks both the task token and the peer's kernel-reported UID. See [process separation](docs/IPC_DEPLOYMENT.md) for socket ownership and group access.

## Tool and model access

Operators choose destinations, permitted arguments, credentials and resource limits. External writes require exact approval. Standing HTTPS reads require explicit permission to send their arguments to the configured destination.

Review which data a tool can send, including path and query values. Provider egress is a separate permission covering prompts, context and results sent by the model runner. Keep framework tools, callbacks, plugins, telemetry and host network access within the same deployment policy.

Treat model output, source text, messages, citations and logs as data. Evaluate answer conclusions against their evidence; quote validation checks that citations match captured text.

## Sandbox

Each job uses fresh user, mount, PID, network and IPC namespaces. The root filesystem is read-only and the working directory is temporary. Trusted setup clears supplementary groups, drops to a separate host UID/GID, removes capabilities and enables `no_new_privs` before starting the code.

A default-deny syscall filter restricts process creation and permitted `ioctl` requests. The sandbox blocks network access and enforces wall-time, output, per-process memory and per-worker-UID process limits. Allocate worker IDs with those shared process limits in mind.

For a non-root broker, provision subordinate UID/GID ranges and the distribution's trusted `newuidmap` and `newgidmap` helpers. Sandbox launch requires valid identity mappings. Run the sandbox tests under the actual service account and maintain the host kernel, resource controls and rootfs. Setup is in [deployment](CUSTOMER_DEPLOYMENT.md#prepare-the-sandbox).

## Review and audit

Reviewer accounts have explicit task scope. Sessions use expiry, CSRF protection, Origin checks and secure cookies for HTTPS deployments. Use an authenticated operator channel for administration and incident decisions.

The HMAC-chained audit log detects changes relative to a retained log head. Store verified heads under separate control. State, checkpoints and backups contain plaintext secrets and task data; protect them with filesystem permissions and your encrypted-storage and backup policy. Keep encryption keys and retained audit heads separate from the backed-up state.

Resolve uncertain outcomes from destination records before resuming the task. The [recovery runbook](docs/RECOVERY.md) covers suspension, backup, restore and reconciliation.

## Report a security issue

Use [GitHub private vulnerability reporting](https://github.com/paulchum/agent-effect-gate/security/advisories/new) for project vulnerabilities. Do not open a public issue with sensitive details. For an active deployment incident, also contact your deployment's private security channel. Include the release version, application checksum, timestamps, stable error codes and a redacted reproduction. Keep credentials, payloads and state snapshots in an access-controlled evidence store.

During this initial preview, security fixes target the latest public release and `main`; no long-term support or response-time commitment is offered.

Coordinate containment and recovery with the operator. Preserve audit heads, suspend affected tasks and reconcile destination outcomes before restarting execution.
