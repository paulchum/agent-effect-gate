import asyncio
import json
from fixture import NativeBase
from agent_effect_gate.integrations.langchain import build_tools


class LangChain(NativeBase):
    def tools(self):
        bundle = build_tools(self.client)
        return bundle, {tool.name:tool for tool in bundle.tools}
    def test_native_structured_tool_schema(self):
        from langchain_core.tools import StructuredTool
        bundle, tools = self.tools()
        self.assertEqual(len(tools), 11)
        for tool in bundle.tools:
            self.assertIsInstance(tool, StructuredTool)
            schema = tool.args_schema.model_json_schema()
            self.assertIn('request_id', schema['properties'])
            self.assertNotIn('token', schema['properties'])
    def test_sync_and_async_invocations(self):
        _, tools = self.tools()
        first = json.loads(tools['aeg_context'].invoke({'request_id':'sync'}))
        second = json.loads(asyncio.run(tools['aeg_context'].ainvoke({'request_id':'async'})))
        self.assertEqual(first['result']['snapshot']['task_id'], second['result']['snapshot']['task_id'])
    def test_native_approval_retry(self):
        _, tools = self.tools()
        args = {'tool_id':'research','arguments_json':'{"path":"/fixture/data","query":{}}','request_id':'native'}
        first = json.loads(tools['aeg_call_tool'].invoke(args))
        self.assertEqual(first['error'], 'approval_required')
        self.broker.approve_tool(first['call_id'], reviewer='test-operator')
        for _ in range(2):
            result = json.loads(asyncio.run(tools['aeg_call_tool'].ainvoke(args)))
            self.assertEqual(result['result']['state'], 'SUCCEEDED')
        self.assertEqual(len(self.hits), 1)
