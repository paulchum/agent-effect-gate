#!/usr/bin/env python3
"""Exercise database upgrade using an explicitly supplied, trusted comparison source tree."""
import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_effect_gate import Broker

SEED = r'''
import json,sys
from pathlib import Path
from agent_effect_gate import Broker, __version__
p=Path(sys.argv[1]); key=(p/'key').read_bytes(); b=Broker(p/'state.sqlite',key)
t=b.create_task('upgrade-task','fixture',{'agents':['main'],'answer_mode':'model','max_requests':20})['main']
def call(rid, op, args):
 r=b.handle(t,{'request_id':rid,'operation':op,'arguments':args});assert r['ok'],r
call('artifact','put_artifact',{'media_type':'text/plain','data_b64':'eA=='})
for _ in range(2):call('same-read','inbox',{})
(p/'fixture.json').write_text(json.dumps({'token':t,'audit':[list(r) for r in b.store.db.execute('SELECT * FROM audit')]}))
b.close()
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-tree',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    source=args.source_tree.resolve()
    if not (source/'agent_effect_gate/__init__.py').is_file():
        parser.error('Provide an explicitly trusted source tree')
    with tempfile.TemporaryDirectory(prefix='aeg-upgrade-') as temporary:
        temp=Path(temporary);key=secrets.token_bytes(32);(temp/'key').write_bytes(key)
        environment={**os.environ,'PYTHONPATH':str(source)}
        subprocess.run([sys.executable,'-c',SEED,str(temp)],cwd=temp,env=environment,check=True,capture_output=True,timeout=30)
        fixture=json.loads((temp/'fixture.json').read_text())
        broker=Broker(temp/'state.sqlite',key)
        try:
            current=[list(r) for r in broker.store.db.execute('SELECT * FROM audit')]
            assert current[:len(fixture['audit'])] == fixture['audit']
            counters=dict(broker.store.db.execute('SELECT requests,read_requests,retry_requests FROM tasks').fetchone())
            assert counters == {'requests':1,'read_requests':2,'retry_requests':0},counters
            assert broker.store.db.execute('SELECT count(*) FROM read_request_hashes').fetchone()[0] == 1
            head=broker.store.verify()
        finally:broker.close()
        broker=Broker(temp/'state.sqlite',key)
        try:assert broker.store.verify() == head
        finally:broker.close()
        report={'successful':True,
                'checks':['real_source_database','audit_prefix_preserved','read_hash_preserved','counters_preserved','reopen_idempotent'],
                'counters':counters,'uses_customer_state':False}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if __name__=='__main__':main()
