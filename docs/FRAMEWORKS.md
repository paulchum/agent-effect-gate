# Frameworks and MCP

Use `GateClient` directly or expose its tools through a framework adapter. Run integrations under the agent's Linux account and connect to the broker over its Unix socket.

## Install

```sh
python3 -m venv /operator/selected/runner-env
python3 install.py --venv /operator/selected/runner-env
```

Install the selected SDK in that environment using your approved dependency lock. Provision the runner's task token, private checkpoint directory, socket path and expected broker UID. Broker state and signing keys stay with the broker account. See [process separation](IPC_DEPLOYMENT.md).

## Python client

```python
from agent_effect_gate.client import GateClient

client = GateClient.unix(
    "/run/aeg/gate.sock",
    "/private/runner/main.token",
    expected_server_uid=10001,
)

context = client.request("context", {}, request_id="inspect-task")
result = client.call_tool(
    "python_docs",
    {"path": "/3/library/json.html", "query": {}},
    request_id="read-docs",
)
```

Use the UID and paths provisioned for your deployment. `arequest()` and `acall_tool()` provide the same operations asynchronously.

`call_tool()` derives stable proposal and execution IDs from the logical request ID. Reuse that ID and the same arguments to recover after a connection failure or approval pause. Changed arguments under the same ID return a conflict. Transport errors are returned to the caller for explicit recovery. Cancelling an async wait leaves an already-dispatched operation in progress.

`view("context")` and `view("answer")` are metered reads. Framework `answer()` and `aanswer()` retrieve fresh answer envelopes from the gate.

## Native toolkits

| Module | Builder |
|---|---|
| `integrations.openai_agents` | `build_tools(client)` returns typed async function tools. |
| `integrations.langchain` | `build_tools(client)` returns structured sync and async tools. |
| `integrations.langgraph` | `build_tool_node(client)` returns a tool node and its bundle. |
| `integrations.pydantic_ai` | `build_tools(client)` returns typed async tools. |
| `integrations.mcp` | `build_server(client)` returns the optional SDK MCP server. |

Each toolkit exposes 11 typed `GateToolkit` functions. `aeg_call_tool` combines proposal and execution; `aeg_execute_tool` resumes an approved call. The other functions cover discovery, context, observations, artifacts, sharing, messages and answers.

Call `ToolBundle.assert_inventory(actual_tools)` to verify the registered tool objects and count. Review graph nodes, handoffs, callbacks and provider-hosted tools separately so every action follows the intended policy.

Dependency declarations are in [pyproject.toml](../pyproject.toml). Run the 13 native workflow tests in an environment containing the selected SDKs:

```sh
python3 verification/native_tests.py --output validation/native-sdk.json
```

Test approval pauses, exact-request resume and uncertain outcomes in the framework workflow. [Validation](../VALIDATION.md) records the supplied environment's SDK status.

## Built-in MCP

The built-in stdio server uses the standard library and exposes the 15 operations listed in [Features](../FEATURES.md#agent-interfaces).

For a separate runner:

```sh
agent-effect-gate-mcp --socket /run/aeg/gate.sock \
  --token-file /private/runner/main.token --broker-uid BROKER_UID
```

For a trusted host that owns broker state:

```sh
agent-effect-gate mcp --state STATE --agent main
```

Replace `BROKER_UID` with the numeric service UID. Both paths use newline-delimited stdio, support initialization and tool calls, and keep human approval and administration on the broker's separate control interface.

`--backend sdk` selects the optional native MCP backend with its 11-function toolkit. Install its SDK and test the connection with the MCP host used in your deployment.

## Model runner

The built-in `OpenAIResponsesAdapter` accepts an operator-selected model and explicit `allow_provider_egress=True`. `models.ResponsesAdapter` is an alias for the same connector. Credentials come from a host environment variable; the connector uses the configured provider endpoint.

Use `model-run` under the broker account or `model-client` under the runner account. Each step proposes one structured gate operation. The final answer is submitted through the gate.

A custom checkpointed model adapter implements `propose(context, last_result)`, `export_state()` and `import_state(state)`. Keep the saved connector configuration consistent with the checkpoint. Framework-specific conversation memory belongs in the adapter's exported state.

## Approval and recovery

The runner saves its exact pending request before dispatch. After review, repeat the invocation with `--resume`. The saved request continues under the current policy and remaining task budgets; a completed run returns its saved result.

For `UNKNOWN` outcomes, preserve the checkpoint and request ID while the operator reconciles destination records. [Recovery](RECOVERY.md) covers the terminal-state update and task resumption.
