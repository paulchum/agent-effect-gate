"""Public archives omit developer state and remain usable without network access."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from check_package import check
from release_files import source_files


class PublicPackaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.workspace = Path(cls.temporary.name).resolve()
        cls.source = cls.workspace / 'source'
        for path in source_files(ROOT):
            target = cls.source / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        cls.private_names = {
            '.git/config', '.venv/lib/private.py', 'venv/lib/private.py', '.env', '.env.local',
            'agent_effect_gate/.env', 'agent_effect_gate/__pycache__/private.py',
            'agent_effect_gate/state/config.json', 'verification/venv/private.py',
            'docs/private/notes.md', 'validation/summary.json', 'validation/core.json',
            'state/tools.json', 'backups/secret.json', 'local-notes.md', 'dist/private.whl',
        }
        for name in cls.private_names:
            target = cls.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('PRIVATE-PACKAGING-TEST-SENTINEL\n')
        private_file = cls.workspace / 'external.py'
        private_file.write_text('PRIVATE-PACKAGING-TEST-SENTINEL\n')
        (cls.source / 'agent_effect_gate/linked.py').symlink_to(private_file)
        cls.private_names.add('agent_effect_gate/linked.py')
        cls.archive = cls.workspace / 'release.zip'
        process = cls.command(cls.source, 'scripts/package.py', '--output', str(cls.archive))
        if process.returncode:
            raise AssertionError(process.stderr)
        cls.report = json.loads(process.stdout)

    @staticmethod
    def command(root, script, *arguments):
        return subprocess.run([sys.executable, str(root / script), *arguments], cwd=root,
                              capture_output=True, text=True, timeout=60)

    def extract_bundle(self, destination):
        with zipfile.ZipFile(self.archive) as archive:
            archive.extractall(destination)
        return destination / 'agent-effect-gate'

    def test_private_files_and_historical_evidence_are_not_distributed(self):
        selected = {path.relative_to(self.source).as_posix() for path in source_files(self.source)}
        self.assertFalse(selected & self.private_names)
        with zipfile.ZipFile(self.archive) as archive:
            names = {name.removeprefix('agent-effect-gate/') for name in archive.namelist()}
            self.assertFalse(names & self.private_names)
            self.assertFalse(any(name.startswith('validation/') for name in names))
            self.assertEqual(names, selected | {
                'MANIFEST.json', 'dist/agent-effect-gate.pyz',
                'dist/agent-effect-gate-source.tar.gz', 'dist/SHA256SUMS',
            })
            for name in archive.namelist():
                self.assertNotIn(b'PRIVATE-PACKAGING-TEST-SENTINEL\n', archive.read(name))
        with zipfile.ZipFile(self.source / 'dist/agent-effect-gate.pyz') as archive:
            self.assertNotIn('payload/agent_effect_gate/linked.py', archive.namelist())
            self.assertNotIn('payload/agent_effect_gate/state/config.json', archive.namelist())

    def test_archive_generation_is_reproducible(self):
        second = self.workspace / 'second.zip'
        process = self.command(self.source, 'scripts/package.py', '--output', str(second))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())

    def test_extracted_bundle_checks_and_installs_offline(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            root = self.extract_bundle(workspace / 'extracted')
            self.assertFalse((root / 'validation').exists())
            process = self.command(root, 'scripts/check_package.py')
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertFalse(json.loads(process.stdout)['evidence_checked'])
            prefix = workspace / 'installed'
            process = self.command(root, 'install.py', '--prefix', str(prefix))
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)['network_requests'], 0)
            for command in ('agent-effect-gate', 'agent-effect-gate-mcp'):
                result = subprocess.run([str(prefix / 'bin' / command), '--help'],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_archive_includes_offline_build_inputs_and_contracts(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            with tarfile.open(self.source / 'dist/agent-effect-gate-source.tar.gz', 'r:gz') as archive:
                names = {name.removeprefix('agent-effect-gate/') for name in archive.getnames()}
                self.assertTrue({
                    'LICENSE', 'install.py', 'build_support.py', 'pyproject.toml',
                    'scripts/build_release.py', 'scripts/release_files.py',
                    'verification/api_contract.json', 'verification/regression_contract.json',
                } <= names)
                self.assertFalse(names & self.private_names)
                self.assertNotIn('MANIFEST.json', names)
                self.assertFalse(any(name.startswith(('dist/', 'validation/')) for name in names))
                for member in archive.getmembers():
                    self.assertTrue(member.isfile())
                    destination = workspace / member.name
                    self.assertTrue(destination.resolve().is_relative_to(workspace))
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.extractfile(member).read())
            root = workspace / 'agent-effect-gate'
            process = self.command(root, 'scripts/build_release.py')
            self.assertEqual(process.returncode, 0, process.stderr)
            process = self.command(root, 'install.py', '--prefix', str(workspace / 'installed'))
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)['network_requests'], 0)

    def test_integrity_check_rejects_changed_source_and_unmanifested_public_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.extract_bundle(Path(temporary))
            extra = root / 'docs/UNLISTED.md'
            extra.write_text('Unrecorded public documentation.\n')
            with self.assertRaisesRegex(ValueError, 'Distribution inventory mismatch'):
                check(root)
            extra.unlink()
            with (root / 'install.py').open('a') as stream:
                stream.write('\n# changed source\n')
            with self.assertRaisesRegex(ValueError, 'Distribution checksum mismatch: install.py'):
                check(root)

    def test_source_archive_must_match_source_even_with_updated_manifest_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.extract_bundle(Path(temporary))
            target = root / 'dist/agent-effect-gate-source.tar.gz'
            buffer = io.BytesIO()
            with tarfile.open(target, 'r:gz') as source, tarfile.open(fileobj=buffer, mode='w:gz') as out:
                for member in source.getmembers():
                    raw = source.extractfile(member).read()
                    if member.name == 'agent-effect-gate/README.md':
                        raw += b'\nChanged archived source.\n'
                        member.size = len(raw)
                    out.addfile(member, io.BytesIO(raw))
            target.write_bytes(buffer.getvalue())
            manifest_path = root / 'MANIFEST.json'
            manifest = json.loads(manifest_path.read_text())
            manifest['files'][target.relative_to(root).as_posix()] = hashlib.sha256(target.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'Source archive content mismatch'):
                check(root)

    def test_historical_evidence_is_an_explicit_separate_check(self):
        self.assertTrue(self.report['verified'])
        self.assertFalse(self.report['evidence_checked'])
        with tempfile.TemporaryDirectory() as temporary:
            root = self.extract_bundle(Path(temporary))
            self.assertFalse(check(root)['evidence_checked'])
            with self.assertRaises(FileNotFoundError):
                check(root, require_evidence=True)


if __name__ == '__main__':
    unittest.main()
