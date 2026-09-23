# Agent Effect Gate

[![CI](https://github.com/paulchum/agent-effect-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/paulchum/agent-effect-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A permission gate for AI agents. Every tool call is checked against the task's policy, held for human approval when required, and written to an audit log.

Agents propose actions like fetching a page, running code or uploading a file. The gate runs each one, holds it for a reviewer, or refuses it. Approvals bind to the exact request, and code runs in a locked-down Linux sandbox.

**Status: initial public preview (0.1.0).** Linux is the supported runtime. Validate the sandbox, optional SDKs and deployment configuration in your own environment before relying on them. See [validation scope](VALIDATION.md).

## Open core

All code and features in this repository are available under the [MIT license](LICENSE), including the review console, audit log, integrations and deployment tools. You can self-host and use the core commercially without a paid license.

Future enterprise extensions will be developed and licensed separately. They are planned, not included or available in this release. See the [open-core boundary](OPEN_CORE.md) and [commercial direction](COMMERCIAL.md).

## How it works

1. **Define a task.** A policy sets which agents can act, which tools they get, which tools need approval, and how many actions, reads and retries the task may use.
2. **The agent proposes.** The gate validates the call and freezes the exact request: destination, arguments, code and payload bytes.
3. **A reviewer decides.** Calls that need approval wait in the review console until a reviewer approves or rejects them.
4. **The gate executes.** The gate makes one execution attempt for the approved request. If the outcome is uncertain, the call is marked unknown and never retried automatically.
5. **The agent answers.** Answers go through the gate, and every citation must quote captured tool output exactly.

## Features

- **Exact approvals.** An approval covers one frozen request. A different request needs its own approval, and changing the policy or tool configuration voids approvals that haven't run. Approvals expire after five minutes by default.
- **Scoped tools.** HTTPS reads from a fixed site and path prefix, HTTPS uploads to a fixed endpoint (approval always required), GitHub code search in named repositories, and Python or shell in the sandbox. Add your own tools through a small Python adapter interface.
- **Operator-owned destinations and secrets.** Agents choose arguments. Operators choose sites, endpoints, credentials and the sandbox filesystem. Tool API keys stay with the executor.
- **Linux sandbox.** Each job gets fresh user, mount, PID, network and IPC namespaces, a read-only root filesystem, a throwaway working directory, syscall filtering, no network access, and limits on time, memory, processes and output.
- **Budgets and a circuit breaker.** Each task has separate action, read and retry budgets plus per-tool call limits. Repeated authorization denials suspend the task automatically.
- **Safe retries.** Retrying a request with the same ID never repeats the action, and reusing an ID with different arguments is rejected.
- **Resumable runs.** The built-in model runner checkpoints before every step, pauses for approval, and resumes the saved request.
- **Audit log.** Proposals, approvals, executions and denials go into an append-only, HMAC-chained log. Keep a copy of the latest log head elsewhere to detect rollback or tampering.
- **Process separation.** Agents connect over a Unix socket with a per-task token, and both sides verify each other's Linux account on every connection. Approval and admin operations stay off the agent's interface.
- **Review console and CLI.** Reviewers sign in with task-scoped accounts, see full request details, and approve, reject or revoke. The CLI adds readiness checks, backup and restore, task suspension and incident tracking.

## Integrations

- **MCP:** stdio server with 15 agent tools
- **Python:** sync and async `GateClient`
- **Frameworks:** OpenAI Agents SDK, LangChain, LangGraph and Pydantic AI
- **Models:** built-in OpenAI Responses runner, or your own adapter

## Requirements

Linux and Python 3.11+. The core uses only the standard library. The review console needs Uvicorn, framework integrations need their SDKs, and the sandbox needs unprivileged user namespaces, util-linux and libseccomp. Non-root sandbox execution also needs subordinate UID/GID ranges and the `newuidmap`/`newgidmap` helpers. See [deployment](CUSTOMER_DEPLOYMENT.md#prepare-the-sandbox) for setup.

## Install

Clone the repository and build the offline application:

```sh
git clone https://github.com/paulchum/agent-effect-gate.git
cd agent-effect-gate
python3 scripts/build_release.py
python3 install.py --prefix "$HOME/.local"
"$HOME/.local/bin/agent-effect-gate" --help
```

Alternatively, download the complete ZIP from [GitHub Releases](https://github.com/paulchum/agent-effect-gate/releases), extract it, and run `python3 install.py --prefix "$HOME/.local"` inside the extracted directory. The ZIP includes the built executable. GitHub's automatic source archives require the build step above.

The build and offline installer need no third-party Python packages. Follow [installation](docs/DEPLOYMENT.md) for Python environments and wheel installation, or [deployment](CUSTOMER_DEPLOYMENT.md) to create a task and start the review console.

Try the synthetic local example without a model API or credentials:

```sh
python3 examples/demo.py
```

## Contributing and support

Read [CONTRIBUTING.md](CONTRIBUTING.md) for development and tests, [SUPPORT.md](SUPPORT.md) for questions and bug reports, and [SECURITY.md](SECURITY.md#report-a-security-issue) for private vulnerability reports. This project is maintained by [@paulchum](https://github.com/paulchum). See the [changelog](CHANGELOG.md) for releases.

## Security model

The gate controls the tool calls routed through it, so give agents the gate's tools and no others. Run the gate and the agent under separate Linux accounts, and keep the state directory, keys and backups private to the gate's account.

## Documentation

[Features](FEATURES.md) · [Frameworks and MCP](docs/FRAMEWORKS.md) · [Process separation](docs/IPC_DEPLOYMENT.md) · [Security](SECURITY.md) · [Design](ASSURANCE.md) · [Recovery](docs/RECOVERY.md) · [Incident reports](docs/REPORTING.md) · [Validation](VALIDATION.md) · [Upgrade notes](REVIEW_FIXES.md)
