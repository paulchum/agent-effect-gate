# Installation and builds

Agent Effect Gate runs on Linux with Python 3.11 or newer. The core uses the Python standard library. Choose an installation below, then follow [deployment](../CUSTOMER_DEPLOYMENT.md) to configure a task, sandbox and reviewer.

## Install the commands

Run from the extracted project under the dedicated broker account:

```sh
python3 scripts/build_release.py
python3 install.py --prefix "$HOME/.local"
"$HOME/.local/bin/agent-effect-gate" --help
"$HOME/.local/bin/agent-effect-gate-mcp" --help
export PATH="$HOME/.local/bin:$PATH"
```

The build step is needed for a Git checkout or source archive; complete release ZIPs already include the executable. The offline installer includes the application, MIT license, review assets and both commands. It installs into a new destination so you can keep the previous installation during an upgrade.

## Install the Python library

Use a virtual environment for Python imports, the reviewer service or framework integrations:

```sh
python3 -m venv "$HOME/aeg-env"
python3 scripts/build_release.py
python3 install.py --venv "$HOME/aeg-env"
"$HOME/aeg-env/bin/python" -I -c 'from agent_effect_gate.client import GateClient; print(GateClient.__name__)'
export PATH="$HOME/aeg-env/bin:$PATH"
```

Install Uvicorn in the broker environment for the reviewer service. Install each framework's SDK in its runner environment. Dependency declarations are in [pyproject.toml](../pyproject.toml); use your approved dependency lock or wheelhouse.

A standard Python installation from the repository or source distribution is also supported:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
agent-effect-gate --version
```

This uses a Python build backend and may download build dependencies. The `install.py` path above is the offline alternative. The project is distributed through GitHub Releases; this guide does not assume a PyPI publication.

## Run the executable directly

```sh
python3 dist/agent-effect-gate.pyz --help
python3 dist/agent-effect-gate.pyz --mcp --help
```

The executable verifies and extracts its bundled application files into a private temporary directory. Select separate protected paths for durable state and credentials.

## Create a local task

The local profile provides task, artifact and answer operations with external tools disabled. It is useful for checking installation and policy setup.

```sh
umask 077
mkdir -p "$HOME/aeg-anchors"
agent-effect-gate init --state "$HOME/aeg-state" \
  --config deploy/local.json --production \
  > "$HOME/aeg-anchors/initial.json"
agent-effect-gate doctor --state "$HOME/aeg-state" \
  --anchor "$HOME/aeg-anchors/initial.json" --production
```

Copy verified audit heads to separately controlled storage. Use [customer deployment](../CUSTOMER_DEPLOYMENT.md) for scoped HTTPS reads and sandboxed code, and [process separation](IPC_DEPLOYMENT.md) for an agent running under another account.

## Build

The executable build is deterministic and uses the standard library:

```sh
python3 scripts/build_release.py
```

To build a wheel, install the build dependencies from your approved source:

```sh
python3 -m pip install -r requirements-build.txt
python3 scripts/build_release.py --wheel
```

The wheel and application both use the version in `agent_effect_gate/_version.py`.

## Test and package

```sh
AEG_TEST_ROOTFS=/trusted/rootfs python3 verification/run_tests.py \
  --require-sandbox --output validation/core.json
python3 verification/native_tests.py --output validation/native-sdk.json
```

`--require-sandbox` requires zero skipped tests, including ownership checks. Use a disposable Linux qualification environment. [Validation](../VALIDATION.md) describes the scope. Build the source archive, manifest and complete ZIP with:

```sh
python3 scripts/package.py --output ../agent-effect-gate.zip
python3 scripts/check_package.py
```

Public packages exclude local validation records. Package integrity is a separate check from deployment qualification. See [releasing](RELEASING.md) for the complete process.
