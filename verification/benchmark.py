#!/usr/bin/env python3
"""Reproducible scaling measurements. No sleeps, no extrapolated timings.

Checkpoint sizes are synthetic journal entries; the second experiment runs real
broker requests end-to-end. Startup/full-audit costs are reported separately.
"""
from __future__ import annotations
import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]))
from agent_effect_gate import Broker

KEY=b'benchmark-fixture-key-not-for-production-000'

def pct(data,p):
    return sorted(data)[min(len(data)-1,int((len(data)-1)*p))]

def bench(total=100000,samples=100):
    results={'python':platform.python_version(),'platform':platform.platform(),
             'sqlite_sync':'FULL','journal_mode':'WAL','samples_per_size':samples,'history_samples':[]}
    with tempfile.TemporaryDirectory() as directory:
        b=Broker(Path(directory)/'history.sqlite',KEY)
        token=b.create_task('task','tenant',{'agents':['main'],'max_requests':100000})['main']
        nonce=0
        for target in [10,1000,4000,20000,100000]:
            with b.store.transaction() as db:
                last=db.execute('SELECT max(seq) FROM audit').fetchone()[0]
                for i in range(last,target):b.store.append(db,'other-task','operator','fixture',{'n':i})
            before=dict(b.store.verification_stats)
            times=[]
            for _ in range(samples):
                nonce+=1;t=time.perf_counter()
                response=b.handle(token,{'request_id':f'history-{nonce}','operation':'context','arguments':{}})
                times.append((time.perf_counter()-t)*1000)
                if not response['ok']:raise RuntimeError(response)
            results['history_samples'].append({'starting_entries':target,'p50_ms':statistics.median(times),
                                              'p95_ms':pct(times,.95),'mean_ms':statistics.mean(times),
                                              'verified_suffix_rows':b.store.verification_stats['tail_rows']-before['tail_rows'],
                                              'hot_path_full_scans':b.store.verification_stats['full_scans']-before['full_scans']})
        t=time.perf_counter();head=b.store.verify();results['explicit_full_audit']={'entries':head['seq'],'seconds':time.perf_counter()-t}
        b.close()
        t=time.perf_counter();b=Broker(Path(directory)/'history.sqlite',KEY);results['startup_seconds']=time.perf_counter()-t;b.close()
        b=Broker(Path(directory)/'requests.sqlite',KEY)
        token=b.create_task('task','tenant',{'agents':['main'],'max_requests':100000})['main']
        t=time.perf_counter();milestones=[];window=[]
        for i in range(1,total+1):
            start=time.perf_counter()
            response=b.handle(token,{'request_id':f'real-{i}','operation':'context','arguments':{}})
            window.append((time.perf_counter()-start)*1000)
            if not response['ok']:raise RuntimeError(response)
            if i in {1000,4000,20000,100000,total}:
                milestones.append({'requests':i,'elapsed_seconds':time.perf_counter()-t,'window_p50_ms':statistics.median(window),
                                   'window_p95_ms':pct(window,.95)})
                window=[]
        elapsed=time.perf_counter()-t
        results['actual_requests']={'count':total,'elapsed_seconds':elapsed,'requests_per_second':total/elapsed,
                                    'milestones':milestones,'verification_stats':dict(b.store.verification_stats)}
        b.store.verify();b.close()
    return results

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--requests',type=int,default=100000);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not 1 <= args.requests <= 100000:parser.error('requests must be between 1 and 100000')
    result=bench(args.requests);text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text)
