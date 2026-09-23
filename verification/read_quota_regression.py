#!/usr/bin/env python3
"""Measure bounded storage for 3,000 inbox calls on a disposable task.

Only this synthetic application's own temporary state is exercised. Successful
reads store request hashes; after quota exhaustion calls must cause zero writes.
"""
import json
import secrets
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_effect_gate import Broker, __version__


def main():
    with tempfile.TemporaryDirectory(prefix='aeg-read-budget-') as temp:
        path = Path(temp) / 'state.sqlite'
        b = Broker(path, secrets.token_bytes(32))
        token = b.create_task('quota-check', 'synthetic', {'agents': ['main'], 'answer_mode': 'model', 'max_requests': 1,
                              'max_read_requests': 2000, 'max_denials': 1})['main']
        def call(i, op='inbox', args=None):
            return b.handle(token, {'request_id': f'request-{i}', 'operation': op, 'arguments': args or {}})
        assert call('action', 'put_artifact', {'media_type': 'text/plain', 'data_b64': 'eA=='})['ok']
        def state():
            b.store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            task = dict(b.store.db.execute('SELECT requests,read_requests,denials,suspended FROM tasks').fetchone())
            return {**task, 'database_bytes': path.stat().st_size,
                    'audit_rows': b.store.db.execute('SELECT count(*) FROM audit').fetchone()[0],
                    'write_cache_rows': b.store.db.execute('SELECT count(*) FROM requests').fetchone()[0],
                    'read_hash_rows': b.store.db.execute('SELECT count(*) FROM read_request_hashes').fetchone()[0]}
        before = state(); start = time.perf_counter()
        responses = [call(i) for i in range(3000)]
        duration = time.perf_counter() - start; after = state()
        assert sum(r['ok'] for r in responses) == 2000
        assert all(r.get('error') == 'read_budget_exhausted' for r in responses[2000:])
        assert before['audit_rows'] == after['audit_rows']
        changes = b.store.db.total_changes; start = time.perf_counter()
        for i in range(3000, 6000): assert call(i)['error'] == 'read_budget_exhausted'
        exhausted_duration = time.perf_counter() - start
        assert b.store.db.total_changes == changes
        final = state(); assert after == final
        b.close()
        print(json.dumps({'passed': True, 'package_version': __version__, 'setup': 'Action budget exhausted; read budget 2000; fresh temporary SQLite database',
                          'calls': 3000, 'accepted_reads': 2000, 'quota_refusals': 1000, 'seconds': round(duration, 3),
                          'before': before, 'after': after, 'database_growth_bytes': after['database_bytes'] - before['database_bytes'],
                          'additional_over_quota_calls': 3000, 'additional_over_quota_seconds': round(exhausted_duration, 3),
                          'additional_over_quota_database_changes': 0, 'additional_over_quota_storage_growth_bytes': 0,
                          'physical_size_measurement': 'SQLite database after WAL checkpoint/TRUNCATE; not a total host disk cap.',
                          'audit_growth_rows': after['audit_rows'] - before['audit_rows']}, indent=2))


if __name__ == '__main__': main()
