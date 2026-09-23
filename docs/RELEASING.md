# Publishing a release

Releases are maintained by `paulchum`. Update `agent_effect_gate/_version.py` and `CHANGELOG.md`, then verify the changes on Linux. Runtime, wheel and source package versions must agree. The release tag is `v` followed by that version.

```sh
python3 -m pip install -r requirements-build.txt
python3 scripts/build_release.py
python3 verification/run_tests.py --output validation/release-core.json
python3 scripts/build_release.py --wheel
python3 -c 'from setuptools.build_meta import build_sdist; build_sdist("dist")'
python3 scripts/package.py --output ../agent-effect-gate.zip
python3 scripts/check_package.py
```

Build and install a wheel from the sdist in a clean environment as CI does. Test the complete ZIP's offline installer outside the checkout. Check that all archives preserve `LICENSE`, that checksums match and that no local state or credentials are included. Package integrity verifies bytes and membership; it does not certify runtime isolation.

Wait for CI on the exact commit to pass. Tag that commit, publish a GitHub release and attach the complete ZIP, executable, wheel, Python sdist and checksums. Compute release checksums after the final artifacts are copied into a clean staging directory. Do not publish automatically to PyPI; that is a separate distribution decision.

Describe actual results and skipped checks in the release notes. Use a GitHub prerelease while deployment qualification remains incomplete. The supported baseline is documented in [VALIDATION.md](../VALIDATION.md). Keep local validation files private unless reviewed and explicitly selected for publication.
