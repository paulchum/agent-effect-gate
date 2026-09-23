"""Actual different-UID data-plane access, with protected admin state unreadable."""
from __future__ import annotations
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from agent_effect_gate import Broker
from agent_effect_gate.ipc import UnixGateServer


@unittest.skipUnless(os.geteuid()==0, 'Different-UID proof requires a disposable Linux test runner with root privileges')
class DifferentUID(unittest.TestCase):
    def test_other_uid_can_use_scoped_socket_but_not_admin_state(self):
        uid=gid=65534
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); base.chmod(0o711)
            state=base/'private'; state.mkdir(mode=0o700)
            key=secrets.token_bytes(32); (state/'admin.key').write_bytes(key); (state/'admin.key').chmod(0o600)
            broker=Broker(state/'state.sqlite',key)
            token=broker.create_task('uid-test','tenant',{'agents':['main']})['main']
            token_file=base/'session.token'; token_file.write_text(token); token_file.chmod(0o600)
            os.chown(token_file,uid,gid)
            server=UnixGateServer(base/'gate.sock',broker,allowed_uids={uid},socket_mode=0o660).start()
            os.chown(base/'gate.sock',0,gid)
            script=r'''
import json,os,socket,struct,sys
sock,token_path,key_path=sys.argv[1:]
assert os.geteuid()==65534
try:
    open(key_path,'rb').read()
except PermissionError:
    protected=True
else:
    raise AssertionError('Broker administrative key was accessible')
def request(operation,rid):
    token=open(token_path).read()
    envelope={'protocol':'aeg-local-v1','token':token,'request':{'request_id':rid,'operation':operation,'arguments':{}}}
    raw=json.dumps(envelope).encode()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(3); s.connect(sock)
        assert struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]==0
        s.sendall(struct.pack('!I',len(raw))+raw)
        def exact(n):
            out=b''
            while len(out)<n:
                chunk=s.recv(n-len(out))
                if not chunk: raise AssertionError('Incomplete frame')
                out+=chunk
            return out
        n=struct.unpack('!I',exact(4))[0]
        assert 0<n<16000000
        return json.loads(exact(n))
context=request('context','read')
approve=request('approve_tool','approve')
assert context['ok'] and context['result']['snapshot']['task_id']=='uid-test'
assert not approve['ok'] and approve['error']=='unknown_operation'
print(json.dumps({'different_uid':True,'scoped_context':True,'admin_file_denied':protected,'admin_operation_denied':True}))
'''
            try:
                result=subprocess.run([sys.executable,'-I','-c',script,str(base/'gate.sock'),str(token_file),str(state/'admin.key')],
                    user=uid,group=gid,extra_groups=[],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertTrue(all(json.loads(result.stdout).values()))
            finally: server.stop(); broker.close()
