import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from agent_effect_gate import Broker, __version__
from agent_effect_gate.cli import initialize
from agent_effect_gate.codec import canonical, seal
from test_real_tools import HTTPFixture

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('aeg_migrate', ROOT / 'scripts/migrate_state.py')
migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)

class ToolCLI(HTTPFixture):
    def test_exact_approval_and_same_id_retry_across_cli_processes(self):
        state = Path(self.directory.name) / 'cli-state'
        config = Path(self.directory.name) / 'cli.json'
        config.write_text(json.dumps({'task_id':'cli','tenant_id':'tenant','sources':[],
            'policy':{'agents':['main'],'local_only':False,'tool_grants':{'docs':{'approval':'required','max_calls':2}}},
            'tools':[{'id':'docs','kind':'http_read','origin':self.origin,'path_prefix':'/docs','query_keys':[],
                      'allow_loopback':True}]}))
        def command(name, *args, raw=None):
            result = subprocess.run([sys.executable,'-m','agent_effect_gate',name,'--state',str(state),*args],
                                    input=raw,capture_output=True,text=True,cwd=ROOT,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout)
        def action(op,args,req):
            return command('serve','--agent','main',raw=json.dumps({'request_id':req,'operation':op,'arguments':args})+'\n')
        command('init','--config',str(config))
        self.assertEqual(action('answer',{},'empty')['result']['answer']['status'],'awaiting_model_answer')
        call = action('propose_tool',{'tool_id':'docs','arguments':{'path':'/docs/report','query':{}}},'propose')['result']['call_id']
        self.assertEqual(action('execute_tool',{'call_id':call},'send')['error'],'approval_required')
        self.assertEqual(self.hits,[])
        self.assertEqual(command('review-tool','--call',call)['prepared_request']['target'],'/docs/report')
        command('approve-tool','--call',call,'--reviewer','operator','--break-glass')
        done = action('execute_tool',{'call_id':call},'send')['result']
        self.assertEqual(done['state'],'SUCCEEDED')
        self.assertEqual(action('execute_tool',{'call_id':call},'send')['result']['state'],'SUCCEEDED')
        self.assertEqual(len(self.hits),1)
        obs = done['observation']
        answer = action('submit_answer',{'text':'The retrieved synthetic count is seven.',
                 'citations':[{'observation_id':obs['observation_id'],'quote':'"count": 7'}],
                 'limitations':['Synthetic server.']},'final')['result']['answer']
        self.assertEqual(answer['text'],'The retrieved synthetic count is seven.')
        self.assertEqual(answer['citations'][0]['provenance']['origin'],self.origin)
        self.assertFalse(answer['truthfulness_verified'])

    def test_version_and_config_reject_model_owned_auth(self):
        result = subprocess.run([sys.executable,'-m','agent_effect_gate','--version'],cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.stdout.strip(),f'agent-effect-gate {__version__}')
        from agent_effect_gate.tool_config import load_tools
        with self.assertRaises(Exception):
            load_tools([{'id':'x','kind':'http_read','origin':self.origin,'path_prefix':'/docs','query_keys':[],
                         'allow_loopback':True,'credential':'model-selected'}])

class Migration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old, self.new = self.root/'old', self.root/'new'
        initialize(self.old, ROOT/'examples/local_task.json')

    def tearDown(self): self.tmp.cleanup()

    def test_backup_preserves_key_sessions_journal_and_source(self):
        source_before = (self.old/'state.sqlite').read_bytes()
        key = (self.old/'admin.key').read_bytes()
        token = (self.old/'sessions/main.token').read_text()
        report = migration.migrate(self.old,self.new)
        self.assertTrue(report['migrated'])
        self.assertEqual((self.old/'state.sqlite').read_bytes(),source_before)
        self.assertEqual((self.new/'admin.key').read_bytes(),key)
        self.assertEqual((self.new/'sessions/main.token').read_text(),token)
        b = Broker(self.new/'state.sqlite',key)
        try:
            r = b.handle(token,{'request_id':'migrated','operation':'answer','arguments':{}})
            self.assertTrue(r['ok'])
            self.assertIn('fields',r['result']['answer'])
        finally:b.close()
        self.assertEqual(self.new.stat().st_mode & 0o777,0o700)

    def test_legacy_signed_policy_without_mode_remains_evidence(self):
        key = (self.old/'admin.key').read_bytes()
        token = (self.old/'sessions/main.token').read_text()
        b = Broker(self.old/'state.sqlite',key)
        with b.store.transaction() as db:
            row = db.execute('SELECT * FROM tasks').fetchone()
            policy = json.loads(row['policy'])
            for name in ('answer_mode','tool_grants','max_observation_bytes'):policy.pop(name,None)
            signed = {'task':row['id'],'tenant':row['tenant'],'version':row['version'],'policy':policy}
            db.execute('UPDATE tasks SET policy=?,policy_mac=? WHERE id=?',
                       (canonical(policy).decode(),seal(key,'policy-v1',signed),row['id']))
            db.execute('DROP TRIGGER audit_sequence')  # Old schema lacks new append guard.
            db.execute('DROP TABLE drafts');db.execute('DROP TABLE observations');db.execute('DROP TABLE tool_calls')
        b.close()
        (self.old/'tools.json').unlink()  # Not present in the 0.1 CLI state format.
        migration.migrate(self.old,self.new)
        b = Broker(self.new/'state.sqlite',key)
        try:
            r=b.handle(token,{'request_id':'legacy','operation':'answer','arguments':{}})
            self.assertTrue(r['ok'],r);self.assertIn('fields',r['result']['answer'])
            self.assertEqual(b.store.verify()['seq'],3)  # Task, migration and first missing-evidence notice; reads are not audit events.
        finally:b.close()

    def test_existing_destination_and_unsafe_key_are_refused(self):
        self.new.mkdir()
        with self.assertRaises(ValueError):migration.migrate(self.old,self.new)
        self.new.rmdir()
        (self.old/'admin.key').chmod(0o644)
        with self.assertRaises(ValueError):migration.migrate(self.old,self.new)
        self.assertFalse(self.new.exists())
