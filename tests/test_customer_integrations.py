"""Offline contract tests for the MCP transport and fixed-origin model connector."""
import json
import os
from unittest.mock import patch
from agent_effect_gate.api_schema import ARGUMENT_SCHEMAS
from agent_effect_gate.broker import SCHEMAS
from agent_effect_gate.codec import canonical
from agent_effect_gate.customer import customer_profile
from agent_effect_gate.mcp_server import MCPServer, VERSIONS
from agent_effect_gate.model_connector import OpenAIResponsesAdapter, ModelConnectorError
from agent_effect_gate.tool_types import ToolResult
from support import Case


class MCP(Case):
    def setUp(self):
        super().setUp(); self.server = MCPServer(self.b, self.tokens['main']); self.wire_id = 0
    def wire(self, method, params=None):
        self.wire_id += 1
        return self.server.handle({'jsonrpc': '2.0', 'id': self.wire_id, 'method': method, 'params': params or {}})
    def initialize(self, version=VERSIONS[0]):
        value = self.wire('initialize', {'protocolVersion': version, 'capabilities': {}, 'clientInfo': {'name': 'contract-test', 'version': '1.0'}})
        self.server.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        return value
    def test_schemas_cover_every_agent_operation_and_no_control_operations(self):
        self.assertEqual(set(ARGUMENT_SCHEMAS), set(SCHEMAS))
        self.assertNotIn('approve_tool', ARGUMENT_SCHEMAS); self.assertNotIn('host_view', ARGUMENT_SCHEMAS)
    def test_tools_require_initialization(self): self.assertEqual(self.wire('tools/list')['error']['code'], -32000)
    def test_initialize_negotiates_known_version(self):
        result = self.initialize('2025-03-26')['result']
        self.assertEqual(result['protocolVersion'], '2025-03-26'); self.assertEqual(set(result['capabilities']), {'tools'})
    def test_unknown_version_returns_supported_version(self): self.assertIn(self.initialize('future')['result']['protocolVersion'], VERSIONS)
    def test_invalid_initialize_does_not_initialize(self):
        self.assertIn('error', self.wire('initialize', {'protocolVersion': VERSIONS[0]})); self.assertIsNone(self.server.version)
    def test_second_initialization_is_refused(self):
        self.initialize(); self.assertIn('error', self.initialize())
    def test_notifications_never_generate_a_response(self):
        self.assertIsNone(self.server.handle({'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': 3}}))
    def test_parse_and_protocol_errors_are_standard_jsonrpc(self):
        self.assertEqual(self.server.handle(b'{')['error']['code'], -32700)
        self.assertEqual(self.server.handle([])['error']['code'], -32600)
        self.assertEqual(self.server.handle({'jsonrpc': '2.0', 'id': True, 'method': 'ping'})['error']['code'], -32600)
    def test_ping_has_no_broker_storage_effect(self):
        before = self.b.store.db.total_changes
        for _ in range(50): self.assertEqual(self.wire('ping')['result'], {})
        self.assertEqual(self.b.store.db.total_changes, before)
    def test_discovery_contains_valid_schemas_and_no_session_secret(self):
        self.initialize(); value = self.wire('tools/list')
        self.assertEqual({t['name'] for t in value['result']['tools']}, {'aeg_' + op for op in SCHEMAS})
        self.assertNotIn(self.tokens['main'], json.dumps(value))
        for tool in value['result']['tools']:
            self.assertFalse(tool['inputSchema']['additionalProperties']); self.assertNotIn('request_id', tool['inputSchema']['required'])
    def test_tools_call_returns_text_and_structured_content(self):
        self.initialize(); result = self.wire('tools/call', {'name': 'aeg_context', 'arguments': {}})['result']
        self.assertFalse(result['isError']); self.assertEqual(json.loads(result['content'][0]['text']), result['structuredContent'])
    def test_legacy_protocol_does_not_send_structured_content(self):
        self.initialize('2024-11-05'); result = self.wire('tools/call', {'name': 'aeg_context'})['result']
        self.assertNotIn('structuredContent', result)
        self.assertNotIn('annotations', self.wire('tools/list')['result']['tools'][0])
    def test_control_plane_is_not_exposed(self):
        self.initialize()
        for name in ['approve_tool', 'set_policy', 'reviewer_login', 'host_view']:
            self.assertEqual(self.wire('tools/call', {'name': 'aeg_' + name})['error']['code'], -32602)
    def test_invalid_arguments_are_tool_error_not_server_crash(self):
        self.initialize(); result = self.wire('tools/call', {'name': 'aeg_context', 'arguments': {'unauthorized': True}})['result']
        self.assertTrue(result['isError']); self.assertEqual(result['structuredContent']['error'], 'invalid_schema')
    def test_idempotency_key_prevents_duplicate_artifacts(self):
        self.initialize(); args = {'name': 'aeg_put_artifact', 'arguments': {'request_id': 'same', 'media_type': 'text/plain', 'data_b64': 'eA=='}}
        a = self.wire('tools/call', args)['result']; b = self.wire('tools/call', args)['result']
        self.assertEqual(a, b); self.assertEqual(self.b.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0], 1)
    def test_tool_discovery_has_bounded_read_quota(self):
        self.p['max_read_requests'] = 2; self.b.replace_policy('task', self.p); self.initialize()
        self.assertIn('result', self.wire('tools/list')); self.assertIn('result', self.wire('tools/list'))
        before = self.b.store.db.total_changes
        self.assertEqual(self.wire('tools/list')['error']['message'], 'read_budget_exhausted')
        self.assertEqual(self.b.store.db.total_changes, before)
    def test_unknown_rpc_method_is_not_implemented(self):
        self.initialize(); self.assertEqual(self.wire('resources/list')['error']['code'], -32601)


class ModelConnector(Case):
    def setUp(self):
        super().setUp(); self.env = patch.dict(os.environ, {'AEG_TEST_MODEL_KEY': 'synthetic-model-credential-not-real'}); self.env.start(); self.addCleanup(self.env.stop)
        self.kw = {'model': 'customer-selected-model', 'prompt': 'Calculate a result with evidence.', 'allow_provider_egress': True, 'credential_env': 'AEG_TEST_MODEL_KEY'}
    @staticmethod
    def output(operation='inbox', arguments=None):
        return {'status': 'completed', 'output': [{'type': 'function_call', 'name': 'gate_action', 'arguments': json.dumps({'operation': operation, 'arguments_json': json.dumps(arguments or {})})}]}
    def invoke(self, document):
        adapter = OpenAIResponsesAdapter(**self.kw)
        response = ToolResult({'body': json.dumps(document)}, json.dumps(document))
        with patch.object(type(adapter._transport), 'request', return_value=response) as request:
            value = adapter.propose({'task_id': 'task'}, None)
        return value, request
    def test_connector_requires_explicit_provider_disclosure_consent(self):
        with self.assertRaises(ValueError): OpenAIResponsesAdapter(**{**self.kw, 'allow_provider_egress': False})
    def test_missing_model_credential_fails_before_request(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError): OpenAIResponsesAdapter(**self.kw)
    def test_fixed_provider_origin_cannot_be_model_selected(self):
        adapter = OpenAIResponsesAdapter(**self.kw); self.assertEqual(adapter._transport.origin, 'https://api.openai.com')
        with self.assertRaises(TypeError): OpenAIResponsesAdapter(**self.kw, base_url='http://example.invalid')
    def test_one_function_call_becomes_broker_envelope(self):
        action, _ = self.invoke(self.output()); self.assertEqual(action['operation'], 'inbox'); self.assertEqual(action['arguments'], {})
    def test_provider_request_disables_storage_parallel_and_remote_tools(self):
        _, request = self.invoke(self.output()); args = request.call_args.args; body = json.loads(args[3])
        self.assertEqual(args[:2], ('POST', '/v1/responses')); self.assertFalse(body['store']); self.assertFalse(body['stream'])
        self.assertFalse(body['parallel_tool_calls']); self.assertEqual(len(body['tools']), 1)
        self.assertTrue(body['tools'][0]['strict']); self.assertEqual(body['tool_choice']['name'], 'gate_action')
        self.assertNotIn('synthetic-model-credential-not-real', args[3].decode()); self.assertEqual(request.call_count, 1)
    def test_incomplete_response_is_refused(self):
        with self.assertRaises(ModelConnectorError): self.invoke({**self.output(), 'status': 'incomplete'})
    def test_multiple_or_unknown_calls_are_refused(self):
        document = self.output(); document['output'] *= 2
        with self.assertRaises(ModelConnectorError): self.invoke(document)
        document = self.output(); document['output'][0]['name'] = 'unmediated_tool'
        with self.assertRaises(ModelConnectorError): self.invoke(document)
    def test_prose_and_refusals_are_not_forwarded_as_answers(self):
        for output in [[{'type': 'message', 'content': 'succeeded'}], [{'type': 'refusal'}]]:
            with self.assertRaises(ModelConnectorError): self.invoke({'status': 'completed', 'output': output})
    def test_reasoning_metadata_is_tolerated(self):
        document = self.output(); document['output'].insert(0, {'type': 'reasoning', 'summary': []})
        self.assertEqual(self.invoke(document)[0]['operation'], 'inbox')
    def test_control_operation_cannot_escape_envelope_schema(self):
        with self.assertRaises(ModelConnectorError): self.invoke(self.output('approve_tool', {'reviewer': 'forged'}))
    def test_non_object_arguments_are_refused(self):
        document = self.output(); document['output'][0]['arguments'] = json.dumps({'operation': 'context', 'arguments_json': '[]'})
        with self.assertRaises(ModelConnectorError): self.invoke(document)
    def test_provider_exceptions_are_sanitized_and_not_retried(self):
        adapter = OpenAIResponsesAdapter(**self.kw)
        with patch.object(type(adapter._transport), 'request', side_effect=OSError('secret provider detail')) as request:
            with self.assertRaises(ModelConnectorError) as caught: adapter.propose({}, None)
        self.assertNotIn('secret provider detail', str(caught.exception)); self.assertEqual(request.call_count, 1)
    def test_input_limit_is_enforced_before_network(self):
        adapter = OpenAIResponsesAdapter(**{**self.kw, 'max_input_bytes': 4096})
        with patch.object(type(adapter._transport), 'request') as request:
            with self.assertRaises(ModelConnectorError): adapter.propose({'large': 'x' * 5000}, None)
        request.assert_not_called()
    def test_customer_profile_enables_scoped_https_and_isolated_code(self):
        config = customer_profile('/opt/aeg/rootfs'); self.assertFalse(config['policy']['local_only'])
        self.assertEqual({t['kind'] for t in config['tools']}, {'http_read', 'linux_sandbox'})
        self.assertEqual(config['tools'][0]['origin'], 'https://docs.python.org')
        self.assertEqual(config['policy']['tool_grants']['compute']['approval'], 'standing')
        self.assertTrue(config['policy']['tool_grants']['python_docs']['allow_argument_egress'])
