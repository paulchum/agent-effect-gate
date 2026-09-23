"""Complete distribution contracts: no feature or behavioral test silently disappears."""
from __future__ import annotations
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from build_release import build, source_files
import install as installer
from agent_effect_gate import __version__


class Distribution(unittest.TestCase):
    def test_complete_api_signature_contract(self):
        contract = json.loads((ROOT / 'verification/api_contract.json').read_text())
        self.assertEqual(len(contract), 37)
        for relative, expected in contract.items():
            with self.subTest(module=relative):
                tree = ast.parse((ROOT / relative).read_text())
                found = []
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        found.append({'name': node.name, 'kind': 'function', 'arguments': ast.dump(node.args, include_attributes=False)})
                    elif isinstance(node, ast.ClassDef):
                        found.append({'name': node.name, 'kind': 'class'})
                        for method in node.body:
                            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                found.append({'name': node.name + '.' + method.name, 'kind': 'method',
                                              'arguments': ast.dump(method.args, include_attributes=False)})
                self.assertTrue(all(item in found for item in expected), relative)

    def test_complete_named_regression_inventory(self):
        expected = set(json.loads((ROOT / 'verification/regression_contract.json').read_text())['required_tests'])
        def ids(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite): yield from ids(item)
                else: yield item.id()
        collected = set(ids(unittest.defaultTestLoader.discover(str(ROOT / 'tests'))))
        self.assertEqual(len(expected), 434)
        self.assertFalse(expected - collected, sorted(expected - collected))

    def test_executable_is_reproducible_and_contains_all_source_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = build(Path(temporary) / 'one.pyz')
            second = build(Path(temporary) / 'two.pyz')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                inventory = json.loads(archive.read('APPLICATION.json'))['files']
                self.assertEqual(set(inventory), set(source_files()))
                self.assertEqual(len(inventory), 41)  # Original 40 files plus the shared exact-byte preview helper.
                self.assertIn('agent_effect_gate/review_preview.py', inventory)
                for name, raw in source_files().items():
                    self.assertEqual(archive.read('payload/' + name), raw)

    def test_both_executable_entry_points_are_runnable(self):
        for arguments in (['--help'], ['--mcp', '--help']):
            result = subprocess.run([sys.executable, '-I', str(ROOT / 'dist/agent-effect-gate.pyz'), *arguments],
                                    cwd='/tmp', capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('agent-effect-gate', result.stdout)

    def test_product_label_reports_release_version(self):
        result = subprocess.run([sys.executable, '-I', str(ROOT / 'dist/agent-effect-gate.pyz'), '--version'],
                                cwd='/tmp', capture_output=True, text=True, timeout=20)
        self.assertEqual(result.stdout.strip(), f'agent-effect-gate {__version__}')
        html = (ROOT / 'agent_effect_gate/web/index.html').read_text()
        self.assertIn('REVIEW CONSOLE</small>', html)
        self.assertNotRegex(html, r'\b\d+\.\d+(?:\.\d+)?rc\d+\b')

    def test_payload_tamper_is_rejected_before_application_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'application.pyz'
            with zipfile.ZipFile(ROOT / 'dist/agent-effect-gate.pyz') as source, zipfile.ZipFile(target, 'w') as out:
                for item in source.infolist():
                    raw = source.read(item.filename)
                    if item.filename == 'payload/agent_effect_gate/__init__.py': raw += b'\n# changed bytes\n'
                    out.writestr(item, raw)
            result = subprocess.run([sys.executable, '-I', str(target), '--help'], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('checksum mismatch', result.stderr)

    def test_prefix_install_retains_both_commands_and_all_library_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / 'prefix'
            result = installer.install(prefix=prefix)
            self.assertEqual(result['package_files'], 41)
            for name, raw in source_files().items():
                self.assertEqual((prefix / 'lib/agent-effect-gate' / name).read_bytes(), raw)
            self.assertEqual((prefix / 'lib/agent-effect-gate/agent_effect_gate/LICENSE').read_bytes(),
                             (ROOT / 'LICENSE').read_bytes())
            for command in result['commands']:
                process = subprocess.run([command, '--help'], cwd='/tmp', capture_output=True, text=True, timeout=20)
                self.assertEqual(process.returncode, 0, process.stderr)

    def test_venv_install_exposes_python_clients_and_framework_builders(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'environment'
            venv.EnvBuilder(with_pip=False).create(target)
            installation = installer.install(venv=target)
            self.assertEqual((Path(installation['library']) / 'LICENSE').read_bytes(),
                             (ROOT / 'LICENSE').read_bytes())
            code = ('from agent_effect_gate.client import GateClient; '
                    'from agent_effect_gate.integrations.common import GateToolkit, ToolBundle; '
                    'from agent_effect_gate.integrations.langgraph import build_tool_node; '
                    'from agent_effect_gate.models import RunCheckpoint, run_client; print("library-ready")')
            result = subprocess.run([str(target / 'bin/python'), '-I', '-c', code],
                                    cwd='/tmp', capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'library-ready')

    def test_installer_refuses_existing_application_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / 'prefix'
            installer.install(prefix=prefix)
            before = (prefix / 'bin/agent-effect-gate').read_bytes()
            with self.assertRaises(ValueError): installer.install(prefix=prefix)
            self.assertEqual(before, (prefix / 'bin/agent-effect-gate').read_bytes())

    def test_installer_refuses_symlinked_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'real').mkdir()
            (root / 'link').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaises(ValueError): installer.install(prefix=root / 'link')
            self.assertFalse(list((root / 'real').iterdir()))

    def test_installer_refuses_writable_installation_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o777)
            try:
                with self.assertRaises(ValueError): installer.install(prefix=root / 'prefix')
            finally: root.chmod(0o700)

    def test_typed_toolkit_and_langgraph_builder_are_not_generic_callbacks(self):
        from agent_effect_gate.integrations.common import GateToolkit
        kit = GateToolkit(None)
        functions = kit.functions()
        self.assertEqual(len(functions), 11)
        self.assertIn('aeg_call_tool', [f.__name__ for f in functions])
        self.assertIn('aeg_execute_tool', [f.__name__ for f in functions])
        self.assertNotIn('gate_request', [f.__name__ for f in functions])
        tree = ast.parse((ROOT / 'agent_effect_gate/integrations/langgraph.py').read_text())
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == 'ToolNode' for node in ast.walk(tree)))

    def test_both_builtin_mcp_paths_have_complete_operation_inventory(self):
        from agent_effect_gate.api_schema import ARGUMENT_SCHEMAS
        self.assertEqual(set(ARGUMENT_SCHEMAS), {
            'context','answer','inbox','list_tools','resolve_field','put_artifact','read_artifact',
            'share_artifact','send_message','propose_release','execute_release','propose_tool',
            'execute_tool','read_observation','submit_answer'})


if __name__ == '__main__':
    unittest.main()
