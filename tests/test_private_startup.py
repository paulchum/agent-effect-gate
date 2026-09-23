"""Defensive startup checks using only locally created files and identities."""
import os
import tempfile
import unittest
from pathlib import Path
from agent_effect_gate.cli import _broker, _read_private, initialize
from agent_effect_gate.client import read_session_token

ROOT=Path(__file__).resolve().parents[1]

class ProtectedStartup(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def test_private_fifo_is_rejected_without_blocking_open(self):
        p=self.root/'fifo';os.mkfifo(p,0o600)
        with self.assertRaises(ValueError): _read_private(p)
        with self.assertRaises(ValueError): read_session_token(p)
    def test_group_readable_state_is_rejected(self):
        state=self.root/'state';initialize(state,ROOT/'examples/sdk_task.json');state.chmod(0o750)
        with self.assertRaises(ValueError): _broker(state)
    def test_database_symlink_is_rejected(self):
        state=self.root/'state';initialize(state,ROOT/'examples/sdk_task.json')
        database=state/'state.sqlite';moved=state/'moved.sqlite';database.rename(moved);database.symlink_to(moved)
        with self.assertRaises(ValueError): _broker(state)
    @unittest.skipUnless(os.geteuid()==0,'Foreign ownership test requires a disposable root test runner')
    def test_wrong_file_owner_is_rejected(self):
        p=self.root/'key';p.write_bytes(b'x'*32);p.chmod(0o600);os.chown(p,65534,65534)
        with self.assertRaises(ValueError): _read_private(p)
    @unittest.skipUnless(os.geteuid()==0,'Foreign ownership test requires a disposable root test runner')
    def test_wrong_state_owner_cannot_be_adopted(self):
        state=self.root/'state';state.mkdir(mode=0o700);os.chown(state,65534,65534)
        with self.assertRaises(ValueError): initialize(state,ROOT/'examples/sdk_task.json')
        self.assertFalse((state/'admin.key').exists())
