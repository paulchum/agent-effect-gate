import copy
import math
import random
import unittest

from agent_effect_gate.codec import Rejected, canonical, exact_keys, identifier, loads, text
from agent_effect_gate.policy import evaluate, json_pointer, validate_policy
from support import Case, policy


class Codec(unittest.TestCase):
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(Rejected): loads('{"operation":"context","operation":"answer"}')

    def test_non_finite_json_rejected(self):
        for raw in ['NaN', 'Infinity', '-Infinity']:
            with self.subTest(raw=raw), self.assertRaises(Rejected): loads(raw)

    def test_invalid_json_and_unicode_rejected(self):
        for raw in [b'\xff', b'{', '\ud800']:
            with self.subTest(raw=repr(raw)), self.assertRaises(Rejected): loads(raw)
        with self.assertRaises(Rejected): text('\ud800')

    def test_nesting_limit(self):
        with self.assertRaises(Rejected): loads('[' * 40 + '0' + ']' * 40)

    def test_cyclic_python_object_rejected(self):
        a = []; a.append(a)
        with self.assertRaises(Rejected): canonical(a)

    def test_large_request_rejected(self):
        with self.assertRaises(Rejected): loads('12345', limit=4)

    def test_non_json_python_values_rejected(self):
        for value in [object(), b'bytes', {1: 'x'}, float('nan'), float('inf'), (1, 2)]:
            with self.subTest(value=repr(value)), self.assertRaises(Rejected): canonical(value)

    def test_strict_identifiers(self):
        for value in ['../path', '', 'A/B', 'unicode-\u0430', 1, ' ']:
            with self.subTest(value=value), self.assertRaises(Rejected): identifier(value)

    def test_canonical_round_trip(self):
        value = {'b': [1, True, None, 2.5], 'a': 'non-ascii: é'}
        self.assertEqual(loads(canonical(value)), value)
        self.assertEqual(canonical({'x': 1, 'a': 2}), canonical({'a': 2, 'x': 1}))

    def test_exact_keys(self):
        with self.assertRaises(Rejected): exact_keys({'x': 1, 'y': 2}, {'x'})
        with self.assertRaises(Rejected): exact_keys([], set())
        self.assertEqual(exact_keys({'x': 1}, {'x'}), {'x': 1})


class PolicyAndEvaluation(unittest.TestCase):
    def test_invalid_policy_variants(self):
        variants = [
            {'agents': []}, {'agents': ['main', 'main']}, {'agents': 'main'},
            {'local_only': 1}, {'local_only': True, 'destinations': ['destination']},
            {'channels': [['main', 'nonmember']]}, {'channels': [['main', 'main']]},
            {'max_requests': 0}, {'max_requests': True}, {'stage': 'unknown'},
            {'fields': []}, {'destinations': 'not-list'}, {'channels': 'not-list'},
        ]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(Rejected): validate_policy(policy(**changed))

    def test_field_validation(self):
        variants = [{'id': '../path'}, {'pointer': 'no-slash'}, {'operation': 'eval'},
                    {'expected_sha256': 'xyz'}, {'operation': 'filter_table'},
                    {'where': {'column': 'x', 'comparison': 'gt', 'value': 1}}]
        for changed in variants:
            p = policy(); p['fields'][0].update(changed)
            with self.subTest(changed=changed), self.assertRaises(Rejected): validate_policy(p)

    def test_duplicate_field_rejected(self):
        p = policy(); p['fields'].append(copy.deepcopy(p['fields'][0]))
        with self.assertRaises(Rejected): validate_policy(p)

    def test_rfc6901_escapes_and_lists(self):
        self.assertEqual(json_pointer({'a/b': {'~x': [9]}}, '/a~1b/~0x/0'), 9)
        for pointer in ['/00', '/-1', '/1', '/a~2b']:
            with self.subTest(pointer=pointer), self.assertRaises(Rejected): json_pointer([9], pointer)

    def test_numeric_transforms(self):
        for op, values, expected in [('sum', [1,2,3], 6), ('mean', [1,2,3], 2),
                                     ('count', [True, None], 2), ('sum', [0.1,0.2], 0.30000000000000004)]:
            field = {'pointer': '', 'operation': op}
            with self.subTest(op=op): self.assertEqual(evaluate(values, field), expected)

    def test_bad_numeric_transforms(self):
        for op, values in [('sum', [True, 1]), ('mean', []), ('sum', 'x'), ('sum', [1e308, 1e308])]:
            with self.subTest(op=op, values=values), self.assertRaises(Rejected): evaluate(values, {'pointer': '', 'operation': op})

    def test_filter_comparisons(self):
        rows = [{'x': 1}, {'x': 2}, {'x': 3}]
        for comp, expected in [('gt', [3]), ('ge', [2,3]), ('eq', [2]), ('lt', [1]), ('le', [1,2])]:
            field = {'pointer': '', 'operation': 'filter_table', 'columns': ['x'],
                     'where': {'column': 'x', 'comparison': comp, 'value': 2}}
            with self.subTest(comp=comp): self.assertEqual([r['x'] for r in evaluate(rows, field)], expected)


class AdversarialInput(Case):
    def test_500_seeded_untrusted_envelopes_fail_safely(self):
        # This generates malformed/local proposals only, never attack traffic.
        rng = random.Random(20260921)
        choices = [None, [], {}, True, 13, 'unstructured final prose',
                   {'operation': 'set_policy', 'arguments': {'local_only': False}},
                   {'request_id': 'x', 'operation': [], 'arguments': {}},
                   {'request_id': 'x', 'operation': 'context', 'arguments': {'system': 'forged'}}]
        for i in range(500):
            raw = copy.deepcopy(rng.choice(choices))
            if isinstance(raw, dict): raw['request_id'] = f'fuzz-{i}'
            result = self.b.handle(self.tokens['main'], raw)
            self.assertFalse(result['ok'], (raw, result))
        self.assertEqual(self.deliveries, [])
        self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0], 0)
        self.assertTrue(self.context()['control']['local_only'])
        self.b.store.verify()
