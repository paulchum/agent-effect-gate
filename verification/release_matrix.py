"""Exhaustively exercise 128 combinations of seven binary release conditions.

This is a finite test of the implementation, not a proof of the entire system.
All adapters are in-memory recording functions; no external actions are taken.
"""
from __future__ import annotations
import itertools
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_effect_gate import Broker
from agent_effect_gate.broker import Sink

DIMENSIONS = ['local_only', 'approved', 'expired', 'policy_changed',
              'correct_agent', 'audience_changed', 'suspended']


def check() -> dict:
    failures = []
    authorized = 0
    checked = 0
    for flags in itertools.product([False, True], repeat=len(DIMENSIONS)):
        conditions = dict(zip(DIMENSIONS, flags))
        effects = []
        now = [1800000000.0]
        sink = Sink('synthetic-audience', '1', lambda payload, key: (effects.append((payload, key)) or {'receipt_id': 'synthetic'}))
        b = Broker(':memory:', secrets.token_bytes(32), clock=lambda: now[0], sinks={'sink': sink})
        try:
            policy = {'agents': ['main', 'worker'], 'local_only': False, 'destinations': ['sink'],
                      'fields': [{'id': 'field', 'label': 'Synthetic field', 'source': 'source', 'version': 'v1', 'pointer': ''}]}
            tokens = b.create_task('task', 'tenant', policy)
            def call(op, args, agent='main'):
                return b.handle(tokens[agent], {'request_id': secrets.token_hex(16), 'operation': op, 'arguments': args})
            artifact = call('put_artifact', {'media_type': 'text/plain', 'data_b64': 'c3ludGhldGlj'})['result']['artifact_id']
            proposal = call('propose_release', {'artifact_id': artifact, 'destination_id': 'sink'})['result']['proposal_id']
            if conditions['approved']: b.approve_release(proposal, reviewer='operator')
            if conditions['expired']: now[0] += 301
            if conditions['policy_changed']: b.replace_policy('task', policy)
            if conditions['local_only']:
                policy.update(local_only=True, destinations=[]); b.replace_policy('task', policy)
            if conditions['audience_changed']:
                b._sinks['sink'] = Sink('different-synthetic-audience', '1', sink.send)
            if conditions['suspended']: b.set_suspended('task', True, operator='operator')
            result = call('execute_release', {'proposal_id': proposal}, 'main' if conditions['correct_agent'] else 'worker')
            expected = (not conditions['local_only'] and conditions['approved'] and not conditions['expired']
                        and not conditions['policy_changed'] and conditions['correct_agent']
                        and not conditions['audience_changed'] and not conditions['suspended'])
            observed = len(effects) == 1
            checked += 1
            authorized += int(observed)
            if observed != expected or len(effects) > 1:
                failures.append({'conditions': conditions, 'result': result, 'effects': len(effects)})
            b.store.verify()
        finally:
            b.close()
    return {'dimensions': DIMENSIONS, 'combinations_checked': checked,
            'authorized_dispatches': authorized, 'failures': failures,
            'external_writes_performed': 0, 'scope': 'Finite gate matrix using synthetic local adapters'}


if __name__ == '__main__':
    result = check()
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result['failures']))
