# Contributing

Bug reports, documentation corrections and focused pull requests are welcome. Discuss substantial behavior or API changes in an issue first. Contributions to this repository are licensed under the existing [MIT license](LICENSE); preserve copyright and third-party notices.

## Development

Use Linux and Python 3.11 or newer. The core has no third-party runtime dependencies. A virtual environment is useful for build tools and optional integrations.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-build.txt
python3 -m pip install -e .
python3 scripts/build_release.py
python3 verification/run_tests.py --output validation/local-core.json
```

The test runner records failures and skips. Sandbox tests need an operator-built rootfs and Linux namespace support. Ownership tests need a disposable runner with the required identities. An ordinary CI pass does not qualify a deployment's isolation. See [VALIDATION.md](VALIDATION.md) for the full qualification command.

Install only the optional SDKs you are working on in a separate framework environment, then run `python3 verification/native_tests.py --output validation/local-native.json`. Missing SDKs are errors in that suite, not evidence that the integrations passed.

## Pull requests

Explain the problem, intended behavior and relevant validation. Add focused tests for meaningful behavior changes. Keep runtime state, tokens, environment files, logs and customer data out of commits. Use synthetic examples. Existing protocol and regression contracts are in `verification/`; preserve them unless an intentional compatibility change is documented.

Maintainer [@paulchum](https://github.com/paulchum) reviews changes and publishes releases. The release procedure is in [docs/RELEASING.md](docs/RELEASING.md). Please keep discussion respectful and focused on the work. Report security issues privately through [SECURITY.md](SECURITY.md#report-a-security-issue).
