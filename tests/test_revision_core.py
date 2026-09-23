import copy
import sqlite3
import tomllib
from pathlib import Path
from unittest.mock import patch
from agent_effect_gate import Broker, IntegrityError
from support import Case, KEY

class RetryFix(Case):
    def test_same_id_succeeds_after_approval(self):
        proposal = self.proposal()
        args = {'proposal_id':proposal}
        self.assertEqual(self.call('execute_release',args,request_id='retry')['error'],'approval_required')
        self.b.approve_release(proposal,reviewer='reviewer')
        self.assertEqual(self.call('execute_release',args,request_id='retry')['result']['state'],'DELIVERED')
        self.assertEqual(self.call('execute_release',args,request_id='retry')['result']['state'],'DELIVERED')
        self.assertEqual(len(self.deliveries),1)

    def test_pending_polls_do_not_suspend_or_spend_new_request_budget(self):
        proposal=self.proposal();args={'proposal_id':proposal}
        self.call('execute_release',args,request_id='waiting')
        before=dict(self.b.store.db.execute('SELECT * FROM tasks').fetchone())
        for _ in range(30): self.call('execute_release',args,request_id='waiting')
        after=dict(self.b.store.db.execute('SELECT * FROM tasks').fetchone())
        self.assertEqual(before['requests'],after['requests'])
        self.assertEqual(before['denials'],after['denials'])
        self.assertFalse(after['suspended'])
        self.b.approve_release(proposal,reviewer='reviewer')
        self.assertEqual(self.call('execute_release',args,request_id='waiting')['result']['state'],'DELIVERED')

    def test_waiting_same_id_survives_restart_and_separate_approval(self):
        proposal=self.proposal();args={'proposal_id':proposal}
        self.call('execute_release',args,request_id='waiting')
        other=Broker(self.path,KEY,clock=self.clock)
        other.approve_release(proposal,reviewer='reviewer');other.close()
        self.b.close();self.b=Broker(self.path,KEY,clock=self.clock,sinks={'approved_sink':self.sink})
        self.assertEqual(self.call('execute_release',args,request_id='waiting')['result']['state'],'DELIVERED')

    def test_failed_write_can_be_reconsidered_without_changing_id(self):
        self.b.set_suspended('task',True,operator='admin')
        args={'media_type':'text/plain','data_b64':'YQ=='}
        self.assertEqual(self.call('put_artifact',args,request_id='retry')['error'],'task_suspended')
        self.b.set_suspended('task',False,operator='admin')
        self.assertTrue(self.call('put_artifact',args,request_id='retry')['ok'])

    def test_retry_cannot_change_fingerprint(self):
        proposal=self.proposal()
        self.call('execute_release',{'proposal_id':proposal},request_id='waiting')
        self.assertEqual(self.call('execute_release',{'proposal_id':'different'},request_id='waiting')['error'],'request_id_conflict')
        self.assertEqual(self.deliveries,[])

class IncrementalAudit(Case):
    def test_requests_never_call_full_verify(self):
        with patch.object(self.b.store,'verify',side_effect=AssertionError('full scan in hot path')):
            for _ in range(10): self.assertTrue(self.call('inbox')['ok'])

    def test_verification_work_is_linear_in_appended_rows(self):
        s=self.b.store
        with s.transaction() as db:
            for i in range(2000): s.append(db,'task','operator','fixture',{'n':i})
        before=dict(s.verification_stats)
        for _ in range(20): self.assertTrue(self.call('inbox')['ok'])
        self.assertEqual(s.verification_stats['full_rows'],before['full_rows'])
        self.assertEqual(s.verification_stats['tail_rows']-before['tail_rows'],0)

    def test_another_connection_suffix_is_checked_once(self):
        other=Broker(self.path,KEY,clock=self.clock)
        try:
            before=self.b.store.verification_stats['tail_rows']
            for i in range(30):
                with other.store.transaction() as db: other.store.append(db,'task','operator','other',{'i':i})
            self.assertTrue(self.call('inbox')['ok'])
            self.assertEqual(self.b.store.verification_stats['tail_rows']-before,30)
        finally:other.close()

    def test_rollback_never_advances_checkpoint(self):
        s=self.b.store;before=dict(s._anchor)
        with self.assertRaises(RuntimeError):
            with s.transaction() as db:
                s.append(db,'task','operator','rolled_back',{})
                raise RuntimeError('rollback')
        self.assertEqual(s._anchor,before)
        self.assertTrue(self.call('inbox')['ok'])
        self.assertEqual(s.verify()['seq'],before['seq'])

    def test_invalid_new_suffix_blocks_next_action(self):
        s=self.b.store;head=s._anchor
        s.db.execute('INSERT INTO audit VALUES(?,?,?,?,?,?,?,?)',
                     (head['seq']+1,self.clock(),'task','agent','forged','{}',head['mac'],'0'*64))
        self.assertEqual(self.call('inbox')['error'],'integrity_or_storage_failure')

    def test_insert_or_replace_cannot_bypass_immutability(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.b.store.db.execute("INSERT OR REPLACE INTO audit SELECT seq,timestamp,task,agent,'changed',details,previous,mac FROM audit WHERE seq=1")

    def test_schema_change_requires_reopen_full_verification(self):
        self.b.store.db.execute('CREATE TABLE unrelated(x)')
        self.assertEqual(self.call('inbox')['error'],'integrity_or_storage_failure')

    def test_startup_full_scan_remains_explicit(self):
        for _ in range(20):self.call('inbox')
        self.b.close();self.b=Broker(self.path,KEY,clock=self.clock)
        self.assertEqual(self.b.store.verification_stats['full_scans'],1)
        self.assertEqual(self.b.store.verification_stats['full_rows'],1)

class Naming(Case):
    def test_console_script_does_not_shadow_hashicorp(self):
        config=tomllib.loads((Path(__file__).parents[1]/'pyproject.toml').read_text())
        self.assertEqual(config['project']['name'],'agent-effect-gate')
        self.assertEqual(set(config['project']['scripts']),{'agent-effect-gate', 'agent-effect-gate-mcp'})
        self.assertFalse((Path(__file__).parents[1]/'boundary_layer').exists())
