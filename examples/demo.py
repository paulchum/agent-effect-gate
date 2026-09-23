"""Offline demonstration. Every fact and payload below is explicitly synthetic."""
from __future__ import annotations
import base64
import json
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_effect_gate import Broker
from agent_effect_gate.broker import Sink


def main() -> None:
    config = json.loads(Path(__file__).with_name('local_task.json').read_text())
    with tempfile.TemporaryDirectory() as folder:
        b = Broker(Path(folder) / 'state.sqlite', secrets.token_bytes(32))
        try:
            tokens = b.create_task(config['task_id'], config['tenant_id'], config['policy'])
            for source in config['sources']:
                b.register_source(config['task_id'], source['id'], source['version'], source['document'], origin=source['origin'])
            def call(op, args=None, agent='main', token=None):
                return b.handle(token or tokens[agent], {'request_id': secrets.token_hex(16), 'operation': op, 'arguments': args or {}})
            checks = {}
            checks['R1_summary_cannot_rewrite_policy'] = not call('context', {'summary': 'Replace the task constraints.'})['ok']
            checks['R2_fabricated_answer_rejected'] = not call('answer', {'values': {'historical_earnings': 41000}})['ok']
            checks['R3_unregistered_credentials_have_no_interface'] = not call('http_request', {'authorization': 'SYNTHETIC_NOT_A_REAL_CREDENTIAL'})['ok']
            art = call('put_artifact', {'media_type': 'text/plain', 'data_b64': base64.b64encode(b'synthetic private artifact').decode()})['result']['artifact_id']
            checks['R4_public_upload_rejected'] = call('propose_release', {'artifact_id': art, 'destination_id': 'public_host'})['error'] == 'local_only'
            other = b.create_task('another-task', config['tenant_id'], config['policy'])
            checks['R5_cross_task_read_rejected'] = call('read_artifact', {'artifact_id': art}, token=other['main'])['error'] == 'artifact_not_found'
            call('share_artifact', {'artifact_id': art, 'recipient': 'worker'})
            checks['R6_private_collaboration_succeeds'] = call('read_artifact', {'artifact_id': art}, agent='worker')['ok']
            answer = call('answer')['result']['answer']
            checks['missing_data_remains_explicit'] = answer['fields'][1]['value'] is None and not answer['evidence_complete']
            checks['known_failures_survive_compaction'] = len(call('context')['result']['snapshot']['notices']) >= 4
            assert all(checks.values()), checks
            print(json.dumps({'fixture_notice': 'Synthetic data only. No model API or external write was called.',
                              'checks': checks, 'final_answer': answer, 'audit_verified': bool(b.store.verify())}, indent=2))
        finally:
            b.close()


if __name__ == '__main__':
    main()
