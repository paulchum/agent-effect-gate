"""Bind validation evidence to the exact implementation and test inputs."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ('agent_effect_gate', 'tests', 'integration_tests', 'verification', 'scripts', 'examples', 'deploy', '.github')
SOURCE_FILES = ('pyproject.toml', 'MANIFEST.in', 'Makefile', 'Dockerfile', 'requirements-build.txt', 'requirements-review.txt', 'install.py', 'build_support.py')

def source_fingerprint(root: Path = ROOT) -> str:
    files = {}
    paths = [root / name for name in SOURCE_FILES]
    for name in SOURCE_DIRS:
        paths.extend((root / name).rglob('*'))
    for path in sorted(paths):
        if (path.is_file() and '__pycache__' not in path.parts and path.suffix not in {'.pyc', '.pyo'}
                and not path.name.startswith('.')):
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

if __name__ == '__main__':
    print(source_fingerprint())
