from __future__ import annotations
import base64
import copy
import tempfile
import unittest
from pathlib import Path
from agent_effect_gate import Broker
from agent_effect_gate.broker import Sink

KEY = b'test-only-key-never-use-in-deployment-000'

class Clock:
    def __init__(self): self.now = 1800000000.0
    def __call__(self): return self.now
    def advance(self, seconds): self.now += seconds


def policy(**changes):
    base = {
        'agents': ['main', 'worker', 'isolated'],
        'answer_mode': 'evidence',
        'channels': [['main', 'worker'], ['worker', 'main']],
        'fields': [{'id': 'revenue', 'label': 'Synthetic revenue', 'source': 'source',
                    'version': 'v1', 'pointer': '/revenue'}],
        'max_denials': 1000,
    }
    base.update(changes)
    return base


class Case(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'state.sqlite'
        self.clock = Clock()
        self.deliveries = []
        self.sink = Sink('approved-example-audience', '1', self.send)
        self.b = Broker(self.path, KEY, clock=self.clock, sinks={'approved_sink': self.sink})
        self.p = policy()
        self.tokens = self.b.create_task('task', 'tenant', self.p)
        self.n = 0

    def tearDown(self):
        self.b.close()
        self.directory.cleanup()

    def send(self, payload, request_id):
        self.deliveries.append((payload, request_id))
        return {'receipt_id': f'receipt-{len(self.deliveries)}'}

    def call(self, operation, arguments=None, *, agent='main', token=None, request_id=None):
        self.n += 1
        return self.b.handle(token or self.tokens[agent], {
            'request_id': request_id or f'request-{self.n}',
            'operation': operation, 'arguments': arguments if arguments is not None else {},
        })

    def source(self, document=None, *, version='v1'):
        return self.b.register_source('task', 'source', version,
                                     {'revenue': 123} if document is None else document,
                                     origin='synthetic-local-fixture')

    def artifact(self, payload=b'private example', *, agent='main'):
        r = self.call('put_artifact', {'media_type': 'text/plain',
                                     'data_b64': base64.b64encode(payload).decode()}, agent=agent)
        self.assertTrue(r['ok'], r)
        return r['result']['artifact_id']

    def allow_release(self):
        self.p['local_only'] = False
        self.p['destinations'] = ['approved_sink']
        self.b.replace_policy('task', self.p)

    def proposal(self, *, approved=False):
        self.allow_release()
        artifact = self.artifact()
        r = self.call('propose_release', {'artifact_id': artifact, 'destination_id': 'approved_sink'})
        self.assertTrue(r['ok'], r)
        proposal = r['result']['proposal_id']
        if approved:
            self.b.approve_release(proposal, reviewer='reviewer')
        return proposal

    def answer(self, **kwargs):
        response = self.call('answer', **kwargs)
        self.assertTrue(response['ok'], response)
        return response['result']['answer']

    def context(self, **kwargs):
        response = self.call('context', **kwargs)
        self.assertTrue(response['ok'], response)
        return response['result']['snapshot']
