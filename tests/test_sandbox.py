import base64
import os
import unittest
from unittest.mock import patch
from agent_effect_gate.sandbox import LinuxSandbox
from support import Case, policy

ROOT=os.environ.get('AEG_TEST_ROOTFS')

@unittest.skipUnless(ROOT,'Set AEG_TEST_ROOTFS to an operator-built clean Linux rootfs to run real isolation tests')
class RealSandbox(Case):
    def setUp(self):
        super().setUp()
        self.sandbox=LinuxSandbox(ROOT)
        self.b._tools={'compute':self.sandbox}
        self.p=policy(answer_mode='model',fields=[],tool_grants={'compute':{'approval':'standing','max_calls':100}})
        self.b.replace_policy('task',self.p)

    def execute_code(self,code,language='python',inputs=None,outputs=None):
        r=self.call('propose_tool',{'tool_id':'compute','arguments':{'language':language,'code':code,'inputs':inputs or {},'outputs':outputs or []}})
        self.assertTrue(r['ok'],r)
        result=self.call('execute_tool',{'call_id':r['result']['call_id']})
        self.assertTrue(result['ok'],result)
        return result['result']

    def test_actual_python_executes_model_chosen_algorithm(self):
        result=self.execute_code('import json,math\nprint(json.dumps({"sqrt":math.sqrt(81),"sum":sum(range(10))}))')
        self.assertEqual(result['state'],'SUCCEEDED')
        self.assertIn('"sqrt": 9.0',result['observation']['text'])
        self.assertIn('"sum": 45',result['observation']['text'])

    def test_actual_shell_pipeline_and_file_output(self):
        result=self.execute_code('printf "one\\ntwo\\n" | wc -l; printf result > report.txt','sh',outputs=['report.txt'])
        self.assertEqual(result['state'],'SUCCEEDED')
        self.assertEqual(result['observation']['data']['stdout'],'2\n')
        self.assertEqual(base64.b64decode(result['observation']['data']['outputs']['report.txt']['data_b64']),b'result')

    def test_task_artifact_input_is_available_without_host_mount(self):
        aid=self.artifact(b'{"numbers":[2,3,5]}')
        result=self.execute_code('import json\nprint(sum(json.load(open("input.json"))["numbers"]))',inputs={'input.json':aid})
        self.assertEqual(result['state'],'SUCCEEDED');self.assertEqual(result['observation']['text'],'10\n')

    def test_network_syscalls_are_blocked(self):
        result=self.execute_code('import socket\ntry:\n socket.socket()\n print("UNEXPECTED_NETWORK")\nexcept PermissionError:\n print("network_denied")')
        self.assertEqual(result['state'],'SUCCEEDED');self.assertEqual(result['observation']['text'],'network_denied\n')

    def test_broker_files_and_host_proc_are_not_visible(self):
        code=f'import os\nprint(os.path.exists({str(self.path)!r}))\nprint(os.path.exists("/proc/1/root"))\nprint(os.path.exists("/etc/passwd"))'
        r=self.execute_code(code);self.assertEqual(r['observation']['text'],'False\nFalse\nFalse\n')

    def test_credentials_and_environment_are_not_inherited(self):
        with patch.dict(os.environ,{'AEG_FAKE_SECRET':'never-real-test-value'}):
            r=self.execute_code('import os\nprint(os.environ.get("AEG_FAKE_SECRET", "absent"))')
        self.assertEqual(r['observation']['text'],'absent\n')

    def test_rootfs_is_read_only(self):
        code='try:\n open("/usr/bin/test-write","w").write("x")\n print("WRITABLE")\nexcept OSError:\n print("readonly")'
        r=self.execute_code(code);self.assertEqual(r['observation']['text'],'readonly\n')

    def test_jobs_have_no_persistent_workspace(self):
        self.assertEqual(self.execute_code('open("persist.txt","w").write("private")')['state'],'SUCCEEDED')
        r=self.execute_code('import os\nprint(os.path.exists("persist.txt"))')
        self.assertEqual(r['observation']['text'],'False\n')

    def test_output_symlinks_are_not_followed(self):
        r=self.execute_code('import os\nos.symlink("/usr/bin/python3","out.bin")',outputs=['out.bin'])
        self.assertEqual(r['state'],'FAILED')
        self.assertEqual(r['observation']['data']['output_errors']['out.bin'],'output_missing_or_unsafe')

    def test_output_and_wall_time_are_bounded(self):
        self.b._tools['compute']=LinuxSandbox(ROOT,timeout_seconds=1,max_output_bytes=1024)
        r=self.execute_code('print("x"*5000)')
        self.assertEqual(r['state'],'FAILED');self.assertEqual(r['observation']['data']['stop_reason'],'output_limit')
        r=self.execute_code('import time; time.sleep(4)')
        self.assertEqual(r['state'],'FAILED');self.assertEqual(r['observation']['data']['stop_reason'],'timeout')

    def test_memory_hard_limit_is_enforced(self):
        r=self.execute_code('try:\n x=bytearray(512*1024*1024)\n print("UNEXPECTED")\nexcept MemoryError:\n print("memory_denied")')
        self.assertEqual(r['state'],'SUCCEEDED');self.assertEqual(r['observation']['text'],'memory_denied\n')

    def test_process_hard_limit_is_enforced(self):
        r=self.execute_code('''import subprocess
children=[]
limited=False
for i in range(25):
 try: children.append(subprocess.Popen(['/usr/bin/python3','-c','import time;time.sleep(0.6)']))
 except (BlockingIOError, PermissionError):
  limited=True
  break
for child in children: child.wait()
print('process_limit_enforced' if limited else 'NOT_ENFORCED')
''')
        self.assertEqual(r['state'],'SUCCEEDED');self.assertEqual(r['observation']['text'],'process_limit_enforced\n')

    def test_new_user_namespace_is_denied_after_setup(self):
        r=self.execute_code('import ctypes\nprint(ctypes.CDLL(None).unshare(0x10000000))')
        self.assertEqual(r['observation']['text'],'-1\n')

    def test_model_cannot_choose_host_argv_or_input_path(self):
        base={'language':'python','code':'print(1)','inputs':{},'outputs':[]}
        for args in [{**base,'rootfs':'/'},{**base,'inputs':{'../admin.key':'art_fake'}},{**base,'outputs':['../../escape']}]:
            r=self.call('propose_tool',{'tool_id':'compute','arguments':args});self.assertFalse(r['ok'])

    def test_no_unsandboxed_fallback(self):
        calls=[]
        def missing(argv,*args,**kwargs):
            calls.append(argv);raise FileNotFoundError('unshare absent')
        with patch('agent_effect_gate.sandbox.capture',side_effect=missing):
            result=self.execute_code('print(1)')
        self.assertEqual(result['state'],'UNKNOWN');self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][0],'/usr/bin/unshare')

    def test_invalid_language_types_cannot_crash_broker(self):
        for language in [None,[],{},True,4]:
            r=self.call('propose_tool',{'tool_id':'compute','arguments':{'language':language,'code':'print(1)','inputs':{},'outputs':[]}})
            self.assertFalse(r['ok'])
        self.assertTrue(self.call('context')['ok'])
