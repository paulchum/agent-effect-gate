#!/usr/bin/env python3
"""Verify public distribution integrity; historical qualification is opt-in."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import zipfile

from release_files import application_files, bundle_files, source_files

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_evidence(root: Path, application_sha256: str) -> str:
    sys.path.insert(0, str(ROOT / 'verification'))
    from evidence import source_fingerprint
    fingerprint = source_fingerprint(root)
    summary = json.loads((root / 'validation/summary.json').read_text())
    if summary['source_fingerprint'] != fingerprint:
        raise ValueError('Evidence does not match the current implementation and tests.')
    if summary['application_sha256'] != application_sha256:
        raise ValueError('Evidence does not match the executable.')
    core = json.loads((root / 'validation/core.json').read_text())
    if core['source_fingerprint'] != fingerprint or not core['source_unchanged_during_run']:
        raise ValueError('Core test source identity mismatch.')
    return fingerprint


def check(root: Path = ROOT, *, require_evidence: bool = False) -> dict:
    manifest = json.loads((root / 'MANIFEST.json').read_text())['files']
    actual = {path.relative_to(root).as_posix() for path in bundle_files(root)}
    if actual != set(manifest):
        raise ValueError('Distribution inventory mismatch: ' + str(sorted(actual ^ set(manifest))))
    for name, expected in manifest.items():
        if _sha256(root / name) != expected:
            raise ValueError('Distribution checksum mismatch: ' + name)

    app = root / 'dist/agent-effect-gate.pyz'
    application_sha256 = _sha256(app)
    sums = (root / 'dist/SHA256SUMS').read_text().splitlines()
    if sums != [application_sha256 + '  ' + app.name]:
        raise ValueError('Application checksum file mismatch.')
    with zipfile.ZipFile(app) as archive:
        inventory = json.loads(archive.read('APPLICATION.json'))['files']
        package_files = {path.relative_to(root).as_posix() for path in application_files(root)}
        if set(inventory) != package_files:
            raise ValueError('Source/executable inventory mismatch.')
        expected_members = {'__main__.py', 'APPLICATION.json', 'LICENSE'} | {
            'payload/' + name for name in inventory}
        if (set(archive.namelist()) != expected_members
                or len(archive.namelist()) != len(expected_members)):
            raise ValueError('Executable member inventory mismatch.')
        for name, expected in inventory.items():
            raw = archive.read('payload/' + name)
            if raw != (root / name).read_bytes() or hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError('Source/executable content mismatch: ' + name)
        if archive.read('__main__.py') != (root / 'scripts/zip_entry.py').read_bytes():
            raise ValueError('Executable bootstrap mismatch.')
        if archive.read('LICENSE') != (root / 'LICENSE').read_bytes():
            raise ValueError('Executable license mismatch.')

    source = root / 'dist/agent-effect-gate-source.tar.gz'
    with tarfile.open(source, 'r:gz') as archive:
        expected_sources = {'agent-effect-gate/' + path.relative_to(root).as_posix(): path
                            for path in source_files(root)}
        members = archive.getmembers()
        if ({item.name for item in members} != set(expected_sources)
                or len(members) != len(expected_sources)):
            raise ValueError('Source archive inventory mismatch.')
        for member in members:
            if not member.isfile():
                raise ValueError('Source archive contains a non-regular member: ' + member.name)
            if archive.extractfile(member).read() != expected_sources[member.name].read_bytes():
                raise ValueError('Source archive content mismatch: ' + member.name)

    report = {'verified': True, 'files': len(manifest), 'application_files': len(inventory),
              'application_sha256': application_sha256, 'source_archive_sha256': _sha256(source),
              'evidence_checked': require_evidence}
    if require_evidence:
        report['evidence_source_fingerprint'] = _check_evidence(root, application_sha256)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--require-evidence', action='store_true',
                        help='Also require local validation/summary.json and core.json to match this build.')
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.root, require_evidence=args.require_evidence), indent=2))
    except (ValueError, KeyError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(2, str(exc) + '\n')


if __name__ == '__main__':
    main()
