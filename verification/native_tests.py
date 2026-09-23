#!/usr/bin/env python3
"""Native SDK evidence. Missing dependencies are errors, never passing skips."""
from __future__ import annotations
import argparse
import importlib.metadata
import importlib.util
import json
import platform
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_effect_gate import __version__
from evidence import source_fingerprint

TARGETS = {'agents': 'openai-agents', 'langchain_core': 'langchain-core',
           'langgraph': 'langgraph', 'pydantic_ai': 'pydantic-ai-slim', 'mcp': 'mcp'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    before = source_fingerprint()
    dependencies = {}
    for module, distribution in TARGETS.items():
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            version = None
        dependencies[distribution] = {'module_available': importlib.util.find_spec(module) is not None,
                                      'installed_version': version}
    start = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.discover(str(ROOT / 'integration_tests')))
    after = source_fingerprint()
    successful = result.wasSuccessful() and not result.skipped and before == after
    value = {'package_version': __version__, 'source_fingerprint': after,
             'source_unchanged_during_run': before == after, 'python': platform.python_version(),
             'successful': successful, 'dependencies': dependencies,
             'status': 'passed' if successful else ('blocked_missing_dependencies' if any(
                 not d['module_available'] for d in dependencies.values()) else 'failed'),
             'tests_run': result.testsRun,
             'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
             'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
             'elapsed_seconds': round(time.monotonic() - start, 3),
             'unsuccessful_tests': [str(test) for test, _ in result.failures + result.errors],
             'external_provider_calls': 0}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2) + '\n')
    return 0 if successful else 1

if __name__ == '__main__':
    raise SystemExit(main())
