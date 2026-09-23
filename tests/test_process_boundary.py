"""End-to-end native process transport; real socket, HTTP and CLI approval."""
import unittest
from examples.framework_demo import demo

class SeparateProcess(unittest.TestCase):
    def test_real_http_and_same_id_approval_across_separate_processes(self):
        result = demo()
        self.assertTrue(result['separate_broker_process'])
        self.assertEqual(result['initial_status'],'awaiting_model_answer')
        self.assertEqual(result['dispatch_count'],1)
        self.assertEqual(result['same_id_approval_retry'],'SUCCEEDED')
        self.assertFalse(result['final_answer']['truthfulness_verified'])
