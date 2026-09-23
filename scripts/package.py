#!/usr/bin/env python3
"""Create reproducible public source and offline distribution archives."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

from build_release import build
from check_package import check
from release_files import bundle_files, source_files

ROOT = Path(__file__).resolve().parents[1]


def source_archive(root: Path = ROOT) -> Path:
    """Build source without recursive dist artifacts or qualification evidence."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for path in source_files(root):
            relative = path.relative_to(root)
            raw = path.read_bytes()
            info = tarfile.TarInfo('agent-effect-gate/' + relative.as_posix())
            info.size = len(raw)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            archive.addfile(info, io.BytesIO(raw))
    target = root / 'dist/agent-effect-gate-source.tar.gz'
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('wb') as out:
        with gzip.GzipFile(filename='', mode='wb', fileobj=out, mtime=0) as compressed:
            compressed.write(buffer.getvalue())
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT.parent / 'agent-effect-gate.zip')
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error('Output archive must be outside the source directory.')
    build()
    source_archive()
    manifest = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in bundle_files(ROOT)}
    (ROOT / 'MANIFEST.json').write_text(json.dumps(
        {'application': 'Agent Effect Gate', 'files': manifest}, indent=2, sort_keys=True) + '\n')
    report = check()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in bundle_files(ROOT, include_manifest=True):
            info = zipfile.ZipInfo('agent-effect-gate/' + path.relative_to(ROOT).as_posix(),
                                   date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    print(json.dumps({'archive': str(args.output), **report}, indent=2))


if __name__ == '__main__':
    main()
