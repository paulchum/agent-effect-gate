.PHONY: build test native check
build:
	python3 scripts/build_release.py
test:
	python3 verification/run_tests.py --output validation/core.json
native:
	python3 verification/native_tests.py --output validation/native-sdk.json
check:
	python3 scripts/check_package.py
