# Deployment examples

Choose a profile, set its paths and permissions, then follow the [deployment guide](../CUSTOMER_DEPLOYMENT.md).

## Task profiles

| File | Use |
|---|---|
| [customer.json](customer.json) | Scoped HTTPS reads and sandboxed code. `setup` generates this profile with your rootfs, task and tenant settings, plus a reviewer account. |
| [local.json](local.json) | Local task, artifact and answer operations with external tools disabled. |
| [research.json](research.json) | Reads from the Python documentation site, with approval for each request. |
| [example-task.txt](example-task.txt) | A prompt for the built-in model runner. |

## Services and connections

[mcp.client.json](mcp.client.json) starts the state-owning stdio MCP command from a trusted host. For a separate runner account, use the scoped socket bridge in [process separation](../docs/IPC_DEPLOYMENT.md).

[aeg-review.service](aeg-review.service) runs the review console under a dedicated service account. [review-proxy.conf](review-proxy.conf) terminates HTTPS at a reverse proxy. Set the account, paths, domain and certificate locations for your host, then test the browser workflow.

## Offline container fixture

[compose.offline.yaml](compose.offline.yaml) and the [Dockerfile](../Dockerfile) provide a core-only stdio MCP container fixture. Set `AEG_IMAGE` to your built image digest, `AEG_STATE_DIR` to the private state volume and `AEG_ANCHOR_FILE` to an independently retained audit head. The default network mode is `none`.

```sh
docker compose -f deploy/compose.offline.yaml run --rm --no-deps -T broker
```

The fixture uses the core-only profile. Use the native deployment guide for HTTPS tools, sandboxed code and the reviewer service. Container execution is a deployment-host check; the supplied validation environment had no Docker runtime.
