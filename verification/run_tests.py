#!/usr/bin/env python3
"""Machine-readable test evidence; --require-sandbox forbids silent skips."""
from __future__ import annotations
import argparse
import json
import os
import platform
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_effect_gate import __version__
from evidence import source_fingerprint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-sandbox', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.require_sandbox and not os.environ.get('AEG_TEST_ROOTFS'):
        parser.error('--require-sandbox needs an operator-built AEG_TEST_ROOTFS')
    fingerprint_before = source_fingerprint()
    start = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    fingerprint_after = source_fingerprint()
    unchanged = fingerprint_before == fingerprint_after
    success = result.wasSuccessful() and unchanged and (not args.require_sandbox or not result.skipped)
    summary = {'source_fingerprint': fingerprint_after, 'source_unchanged_during_run': unchanged,
        'package_version': __version__, 'python': platform.python_version(),
        'platform': platform.system(), 'machine': platform.machine(),
        'tests_run': result.testsRun, 'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
        'elapsed_seconds': round(time.monotonic() - start, 3),
        'required_sandbox': args.require_sandbox, 'successful': success,
        'test_failures': [str(test) for test, _ in result.failures + result.errors],
        'skipped_tests': [{'test': str(test), 'reason': reason} for test, reason in result.skipped]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    raise SystemExit(0 if success else 1)


if __name__ == '__main__':
    main()
