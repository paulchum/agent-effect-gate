#!/usr/bin/env python3
"""Build the deterministic application with no network or third-party build dependency."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile
from release_files import application_files

ROOT = Path(__file__).resolve().parents[1]


def source_files(root: Path = ROOT) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in application_files(root)}


def build(destination: Path | None = None) -> Path:
    target = destination or ROOT / 'dist' / 'agent-effect-gate.pyz'
    target.parent.mkdir(parents=True, exist_ok=True)
    files = source_files()
    inventory = {'application': 'Agent Effect Gate', 'files': {
        name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
    entries = {'__main__.py': (ROOT / 'scripts/zip_entry.py').read_bytes(),
               'LICENSE': (ROOT / 'LICENSE').read_bytes(),
               'APPLICATION.json': (json.dumps(inventory, indent=2, sort_keys=True) + '\n').encode(),
               **{'payload/' + name: raw for name, raw in files.items()}}
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    (target.parent / 'SHA256SUMS').write_text(hashlib.sha256(target.read_bytes()).hexdigest() + '  ' + target.name + '\n')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--wheel', action='store_true', help='Also build a standards-compliant wheel using setuptools.')
    args = parser.parse_args()
    artifact = build(args.output)
    print(str(artifact))
    if args.wheel:
        subprocess.run([sys.executable, '-c', 'from setuptools.build_meta import build_wheel; build_wheel("dist")'],
                       cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
