"""Real OpenAI SDK schema + dispatch tests. Missing SDK is an ERROR, not a skip."""
import asyncio
import json
from fixture import NativeBase
from agent_effect_gate.integrations.openai_agents import build_tools


class OpenAIAgents(NativeBase):
    def tools(self):
        from agents import Agent, set_tracing_disabled
        set_tracing_disabled(True)  # Test must not send observations to a tracer.
        bundle = build_tools(self.client)
        agent = Agent(name='AEG runtime test', tools=list(bundle.tools))
        bundle.assert_inventory(agent.tools)
        return bundle, {tool.name:tool for tool in bundle.tools}
    async def invoke(self, tool, arguments):
        from agents.tool_context import ToolContext
        from agents.tool import invoke_function_tool
        raw = json.dumps(arguments)
        context = ToolContext(context=None, tool_name=tool.name,
                              tool_call_id='sdk-call', tool_arguments=raw)
        return json.loads(await invoke_function_tool(function_tool=tool, context=context, arguments=raw))
    def test_native_schemas(self):
        bundle, tools = self.tools()
        self.assertEqual(len(tools), 11)
        for tool in bundle.tools:
            self.assertTrue(tool.strict_json_schema)
            schema = tool.params_json_schema
            self.assertFalse(schema['additionalProperties'])
            self.assertIn('request_id', schema['properties'])
            self.assertNotIn('token', schema['properties'])
            self.assertEqual(set(schema['properties']), set(schema['required']))
    def test_native_dispatch_and_same_id_approval_retry(self):
        _, tools = self.tools()
        arguments = {'tool_id':'research', 'arguments_json':'{"path":"/fixture/data","query":{}}',
                     'request_id':'same-native-action'}
        first = asyncio.run(self.invoke(tools['aeg_call_tool'], arguments))
        self.assertEqual(first['error'], 'approval_required'); self.assertEqual(self.hits, [])
        self.broker.approve_tool(first['call_id'], reviewer='test-operator')
        for _ in range(2):
            result = asyncio.run(self.invoke(tools['aeg_call_tool'], arguments))
            self.assertEqual(result['result']['state'], 'SUCCEEDED')
        self.assertEqual(len(self.hits), 1)
    def test_native_answer_must_be_submitted(self):
        bundle, tools = self.tools()
        before = bundle.answer(request_id='before')['result']['answer']
        self.assertIsNone(before['text'])
        result = asyncio.run(self.invoke(tools['aeg_submit_answer'], {
            'text':'Model-authored test prose', 'citations_json':'[]',
            'limitations_json':'["Local synthetic test"]', 'request_id':'final'}))
        self.assertTrue(result['ok'])
        self.assertFalse(bundle.answer(request_id='after')['result']['answer']['truthfulness_verified'])
