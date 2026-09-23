# Validation

This initial public preview includes automated checks for the core application, packaging and installed workflows. It is not a certification of a production deployment.

## Public CI

[GitHub Actions](https://github.com/paulchum/agent-effect-gate/actions/workflows/ci.yml) runs on Ubuntu with Python 3.11, 3.12 and 3.13 for pushes and pull requests. Each job builds the executable, runs the core suite, checks synthetic authorization and read quotas, installs the offline package, builds a wheel and sdist, rebuilds a wheel from that sdist, and exercises isolated installed clients and recovery workflows. It also checks the complete release archive.

The job summary and downloadable report show actual passes, failures and skip reasons for each commit. Real sandbox and different-UID checks can be skipped on ordinary hosted runners. Those skips remain visible; a passing hosted job does not establish sandbox qualification. Native SDK, browser HTTPS and live-provider tests are not part of the core CI job.

## Reproduce the core checks

Use Linux and Python 3.11 or newer:

```sh
python3 scripts/build_release.py
python3 verification/run_tests.py --output validation/local-core.json
python3 verification/release_matrix.py
python3 verification/read_quota_regression.py
python3 scripts/package.py --output ../agent-effect-gate.zip
python3 scripts/check_package.py
```

Core results bind to a fingerprint of application and test inputs. Do not edit those files during the test run. Package integrity checks compare source, executable, source archive, license and manifest contents; they do not imply runtime security qualification.

## Deployment qualification

| Area | Required check before relying on it |
| --- | --- |
| Linux sandbox | Build a trusted disposable rootfs, provision namespace and seccomp support, then run real sandbox tests. |
| Non-root isolation | Install mapping helpers and delegated UID/GID ranges; verify execution under the actual service account. |
| Separate identities | Verify socket ownership, kernel peer credentials and protected files on the deployment host. |
| Optional SDKs | Install the selected pinned dependencies and run the native integration suite in its intended environment. |
| Review console | Verify browser login, cookies, Origin/CSRF handling and TLS at the deployed HTTPS origin. |
| Provider and tools | Test the chosen provider, destinations and credentials under the deployment policy. |
| Recovery | Drill fencing, backups, restore, independent audit-head retention and destination reconciliation. |

For a disposable Linux qualification runner with all prerequisites provisioned:

```sh
python3 scripts/build_rootfs.py /trusted/rootfs
AEG_TEST_ROOTFS=/trusted/rootfs python3 verification/run_tests.py \
  --require-sandbox --output validation/qualified-core.json
python3 verification/native_tests.py --output validation/native-sdk.json
```

`--require-sandbox` rejects every skip, including ownership tests that need a disposable root-capable runner. That suite does not replace non-root service acceptance. Never point qualification tests at production state. Follow [deployment](CUSTOMER_DEPLOYMENT.md) and [recovery](docs/RECOVERY.md).

## Historical evidence

The supplied project contained older validation logs and a summary for a different source fingerprint. Those records are preserved locally and excluded from the public repository and release assets. Their historical test counts, sandbox results and executable hashes are not claims about this release. New reports are written to the ignored `validation/` directory or retained as CI artifacts.

See [release instructions](docs/RELEASING.md) for artifact construction and publication.
