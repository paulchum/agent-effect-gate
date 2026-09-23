import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verification.release_matrix import check

class ReleaseGateMatrix(unittest.TestCase):
    def test_all_128_release_gate_combinations(self):
        result = check()
        self.assertEqual(result['combinations_checked'], 128)
        self.assertEqual(result['authorized_dispatches'], 1)
        self.assertEqual(result['failures'], [])
