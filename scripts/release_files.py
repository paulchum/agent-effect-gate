"""Explicit public release inventory shared by builders and integrity checks.

Keep generated artifacts, execution state, editor files and local environments out
of releases even when a build runs from a developer's working directory.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT_FILES = frozenset({
    'LICENSE', 'NOTICE', '.gitignore', '.gitattributes', '.editorconfig', '.dockerignore',
    'Dockerfile', 'Makefile', 'MANIFEST.in', 'install.py', 'build_support.py',
    'pyproject.toml', 'requirements-build.txt', 'requirements-review.txt',
    *{name + '.md' for name in (
        'README', 'FEATURES', 'REVIEW_FIXES', 'VALIDATION', 'CUSTOMER_DEPLOYMENT',
        'ASSURANCE', 'SECURITY', 'CONTRIBUTING', 'CODE_OF_CONDUCT', 'GOVERNANCE',
        'OPEN_CORE', 'COMMERCIAL', 'ROADMAP', 'SUPPORT', 'CHANGELOG',
    )},
})
SOURCE_DIRECTORIES = {
    'agent_effect_gate': frozenset({'.py', '.html', '.css', '.js', '.json'}),
    'scripts': frozenset({'.py'}),
    'tests': frozenset({'.py', '.json', '.txt'}),
    'integration_tests': frozenset({'.py', '.json', '.txt'}),
    'verification': frozenset({'.py', '.json'}),
    'examples': frozenset({'.py', '.json', '.md', '.txt'}),
    'docs': frozenset({'.md', '.png', '.jpg', '.jpeg', '.svg'}),
    'deploy': frozenset({'.json', '.md', '.txt', '.service', '.conf', '.yaml', '.yml'}),
    '.github': frozenset({'.md', '.yaml', '.yml'}),
}
EXCLUDED_DIRECTORIES = frozenset({
    '__pycache__', 'build', 'dist', 'validation', 'venv', 'env', 'node_modules',
    'site-packages', 'state', 'sessions', 'backups', 'private', 'secrets',
})
DISTRIBUTION_FILES = (
    'dist/agent-effect-gate.pyz',
    'dist/agent-effect-gate-source.tar.gz',
    'dist/SHA256SUMS',
)


def _public_directory(name: str) -> bool:
    return (not name.startswith('.') and name not in EXCLUDED_DIRECTORIES
            and not name.endswith('.egg-info'))


def source_files(root: Path) -> list[Path]:
    """Return regular, allowlisted source files without following symbolic links."""
    selected = [root / name for name in ROOT_FILES
                if (root / name).is_file() and not (root / name).is_symlink()]
    for directory, extensions in SOURCE_DIRECTORIES.items():
        parent = root / directory
        if not parent.is_dir() or parent.is_symlink():
            continue
        for current, directories, names in os.walk(parent, followlinks=False):
            directories[:] = [name for name in directories
                              if _public_directory(name)
                              and not (Path(current) / name).is_symlink()]
            for name in names:
                path = Path(current) / name
                if (not name.startswith('.') and path.is_file() and not path.is_symlink()
                        and (path.suffix in extensions
                             or (directory == '.github' and name == 'CODEOWNERS'))):
                    selected.append(path)
    return sorted(selected, key=lambda path: path.relative_to(root).as_posix())


def application_files(root: Path) -> list[Path]:
    return [path for path in source_files(root)
            if path.relative_to(root).parts[0] == 'agent_effect_gate']


def bundle_files(root: Path, *, include_manifest: bool = False) -> list[Path]:
    """Source plus the three deliberately generated offline release artifacts."""
    selected = source_files(root)
    names = (*DISTRIBUTION_FILES, 'MANIFEST.json') if include_manifest else DISTRIBUTION_FILES
    for name in names:
        path = root / name
        if not path.is_file() or path.is_symlink() or path.parent.is_symlink():
            raise ValueError('Missing or linked distribution artifact: ' + name)
        selected.append(path)
    return sorted(selected, key=lambda path: path.relative_to(root).as_posix())
