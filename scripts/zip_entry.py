"""Run the application from a verified, private-owner source extraction.

Only public application code is unpacked. State and credentials must be placed in
explicit operator-controlled paths, never inside this temporary source directory.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import sys
import tempfile
import zipfile


def main():
    archive = Path(sys.argv[0]).absolute()
    with zipfile.ZipFile(archive) as bundle:
        inventory = json.loads(bundle.read('APPLICATION.json'))['files']
        expected = {'payload/' + name for name in inventory}
        actual = {item.filename for item in bundle.infolist() if item.filename.startswith('payload/')}
        if actual != expected or len(bundle.namelist()) != len(set(bundle.namelist())):
            raise SystemExit('Application archive inventory mismatch.')
        with tempfile.TemporaryDirectory(prefix='aeg-application-') as temporary:
            root = Path(temporary)
            # Sandbox workers may run as another unprivileged UID. This directory
            # contains public code only; ownership still prevents modification.
            root.chmod(0o755)
            for name, expected_hash in inventory.items():
                path = PurePosixPath(name)
                if path.is_absolute() or '..' in path.parts or path.parts[0] != 'agent_effect_gate':
                    raise SystemExit('Unsafe application member.')
                raw = bundle.read('payload/' + name)
                if hashlib.sha256(raw).hexdigest() != expected_hash:
                    raise SystemExit('Application member checksum mismatch.')
                target = root.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with target.open('xb') as stream:
                    stream.write(raw)
                target.chmod(0o644)
            module = 'agent_effect_gate'
            if len(sys.argv) > 1 and sys.argv[1] == '--mcp':
                module = 'agent_effect_gate.integrations.mcp'
                del sys.argv[1]
            sys.path.insert(0, str(root))
            runpy.run_module(module, run_name='__main__', alter_sys=True)


if __name__ == '__main__':
    main()
