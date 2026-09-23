#!/usr/bin/env python3
"""Build a CLEAN Linux rootfs from trusted system Python, shell and a few utilities.

Run once as an operator. Never pass model-selected binaries or directories here.
The output must remain operator-owned and unwritable by agents. This script copies
only the standard library and binary dependencies, not /home, /etc or site-packages.
"""
from __future__ import annotations
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


def build(destination: Path) -> dict:
    destination = destination.absolute()
    destination.mkdir(mode=0o755, parents=False, exist_ok=False)
    copied = set()
    def copy_binary(path):
        path = Path(path)
        if str(path) in copied:
            return
        copied.add(str(path))
        target = destination / str(path).lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path.resolve(), target)
        # All inputs to ldd are operator-selected system ELF files, never untrusted.
        result = subprocess.run(['/usr/bin/ldd', str(path)], capture_output=True, text=True, timeout=10)
        for dep in re.findall(r'(/[^\s()]+)', result.stdout):
            if Path(dep).is_file(): copy_binary(dep)
    version = subprocess.check_output(['/usr/bin/python3','-c','import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")'], text=True).strip()
    stdlib = Path('/usr/lib/python' + version)
    for binary in ['/usr/bin/python3','/bin/sh','/bin/cat','/bin/ls','/usr/bin/wc','/usr/bin/head','/usr/bin/sha256sum','/bin/true']:
        copy_binary(binary)
    shutil.copytree(stdlib, destination / stdlib.relative_to('/'), dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__','test','tests','tkinter','turtledemo','idlelib','ensurepip','site-packages'))
    for shared in stdlib.rglob('*.so'):
        if (destination / shared.relative_to('/')).exists(): copy_binary(shared)
    for name in ('work','tmp','proc','dev'):
        (destination / name).mkdir(exist_ok=True)
    (destination / 'dev/null').touch()
    entries = {}
    for path in sorted(destination.rglob('*')):
        if path.is_file(): entries[str(path.relative_to(destination))] = hashlib.sha256(path.read_bytes()).hexdigest()
    revision = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    manifest = {'format':'aeg-rootfs-v1','revision':revision,'python':version,'files':entries}
    (destination / '.aeg-rootfs.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return {'rootfs':str(destination),'revision':revision,'files':len(entries)}

if __name__ == '__main__':
    if len(sys.argv) != 2: raise SystemExit('Usage: python scripts/build_rootfs.py NEW_DIRECTORY')
    print(json.dumps(build(Path(sys.argv[1])), indent=2))
