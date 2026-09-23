#!/usr/bin/env python3
"""Offline CLI and Python-library installation into a private prefix or an explicit virtual environment."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent


def no_links(path: Path) -> Path:
    path = path.expanduser().absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError('Symbolic links are not accepted in installation directories.')
    return path


def owned_directory(path: Path) -> None:
    no_links(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o755)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('Installation directories must be operator-owned and not group/world writable.')
    # Writable non-sticky ancestors allow an unrelated account to replace code.
    for ancestor in path.parents:
        info = ancestor.stat()
        if info.st_mode & 0o022 and not (info.st_mode & 0o1000):
            raise ValueError('An installation ancestor is writable by another account.')


def payload() -> tuple[dict[str, bytes], str, bytes]:
    source = ROOT / 'dist/agent-effect-gate.pyz'
    sums = ROOT / 'dist/SHA256SUMS'
    expected = {line.split(maxsplit=1)[1].strip(): line.split(maxsplit=1)[0]
                for line in sums.read_text().splitlines() if line.strip()}
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if expected.get(source.name) != digest:
        raise ValueError('Application checksum mismatch. Rebuild before installing.')
    with zipfile.ZipFile(source) as bundle:
        inventory = json.loads(bundle.read('APPLICATION.json'))['files']
        actual = {item.filename for item in bundle.infolist() if item.filename.startswith('payload/')}
        if actual != {'payload/' + name for name in inventory} or len(bundle.namelist()) != len(set(bundle.namelist())):
            raise ValueError('Application inventory mismatch.')
        source_license = ROOT / 'LICENSE'
        license_bytes = (bundle.read('LICENSE') if 'LICENSE' in bundle.namelist()
                         else source_license.read_bytes())
        if not license_bytes.strip():
            raise ValueError('Application license is missing or empty.')
        if source_license.is_file() and source_license.read_bytes() != license_bytes:
            raise ValueError('Application license does not match the source license. Rebuild before installing.')
        files = {}
        for name, checksum in inventory.items():
            item = PurePosixPath(name)
            if item.is_absolute() or '..' in item.parts or item.parts[0] != 'agent_effect_gate':
                raise ValueError('Unsafe application member.')
            raw = bundle.read('payload/' + name)
            if hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError('Application member checksum mismatch.')
            files[name] = raw
    return files, digest, license_bytes


def install(*, prefix: Path | None = None, venv: Path | None = None) -> dict:
    files, digest, license_bytes = payload()
    interpreter = sys.executable
    if venv is not None:
        venv = no_links(venv)
        if not (venv / 'pyvenv.cfg').is_file():
            raise ValueError('Create the virtual environment before installing into it.')
        interpreter = str(venv / 'bin/python')
        probe = subprocess.run([interpreter, '-I', '-c',
            'import json,sys,sysconfig;print(json.dumps({"prefix":sys.prefix,"purelib":sysconfig.get_path("purelib")}))'],
            check=True, capture_output=True, text=True, timeout=15)
        settings = json.loads(probe.stdout)
        parent = no_links(Path(settings['purelib']))
        if Path(settings['prefix']).resolve() != venv.resolve() or not parent.is_relative_to(venv):
            raise ValueError('The selected interpreter does not belong to this virtual environment.')
        destination = parent / 'agent_effect_gate'
        binary = venv / 'bin'
        library_parent = parent
    else:
        prefix = no_links(prefix or Path.home() / '.local')
        parent = prefix / 'lib'
        destination = parent / 'agent-effect-gate'
        binary = prefix / 'bin'
        library_parent = destination
    for directory in (parent, binary):
        owned_directory(directory)
    launchers = {binary / 'agent-effect-gate': 'agent_effect_gate',
                 binary / 'agent-effect-gate-mcp': 'agent_effect_gate.integrations.mcp'}
    for path in (destination, *launchers):
        no_links(path)
        if os.path.lexists(path):
            raise ValueError('Application already exists. Choose an empty prefix or virtual environment.')
    temporary = Path(tempfile.mkdtemp(prefix='.aeg-install-', dir=parent))
    created: list[Path] = []
    try:
        for name, raw in files.items():
            target = temporary / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with target.open('xb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            target.chmod(0o644)
        license_target = temporary / 'agent_effect_gate/LICENSE'
        with license_target.open('xb') as stream:
            stream.write(license_bytes); stream.flush(); os.fsync(stream.fileno())
        license_target.chmod(0o644)
        if venv is not None:
            staged = temporary / 'agent_effect_gate'
        else:
            staged = temporary
            staged.chmod(0o755)
        os.rename(staged, destination)
        created.append(destination)
        bootstrap = ('import runpy,sys;sys.path.insert(0,sys.argv[1]);'
                     'module=sys.argv[2];sys.argv=[module]+sys.argv[3:];'
                     'runpy.run_module(module,run_name="__main__",alter_sys=True)')
        for path, module in launchers.items():
            arguments = [interpreter, '-I', '-c', bootstrap, str(library_parent), module]
            text = '#!/usr/bin/env python3\nimport os,sys\nos.execv(' + repr(interpreter) + ', ' + repr(arguments) + ' + sys.argv[1:])\n'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
            created.append(path)
            with os.fdopen(fd, 'w') as stream:
                stream.write(text); stream.flush(); os.fsync(stream.fileno())
        return {'installed': True, 'application_sha256': digest, 'package_files': len(files),
                'library': str(destination), 'python': interpreter,
                'commands': [str(path) for path in launchers], 'network_requests': 0}
    except BaseException:
        for path in reversed(created):
            if path.is_dir(): shutil.rmtree(path)
            else: path.unlink(missing_ok=True)
        raise
    finally:
        if temporary.exists(): shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--prefix', type=Path)
    group.add_argument('--venv', type=Path, help='Also expose the Python client and integrations to this existing virtual environment.')
    args = parser.parse_args()
    try:
        print(json.dumps(install(prefix=args.prefix, venv=args.venv), indent=2))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        parser.exit(2, 'Installation refused: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
