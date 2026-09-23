import asyncio
import json
import os
import sys
from pathlib import Path
from fixture import NativeBase
from agent_effect_gate.integrations.mcp import build_server


def envelope(result):
    if result.is_error: raise AssertionError('MCP protocol/tool error: '+str(result.content))
    return json.loads(''.join(block.text for block in result.content if block.type == 'text'))


class MCP(NativeBase):
    def test_real_protocol_lists_only_scoped_tools(self):
        from mcp import Client
        async def run():
            async with Client(build_server(self.client), raise_exceptions=True) as client:
                listing = await client.list_tools()
                self.assertEqual(len(listing.tools), 11)
                for tool in listing.tools:
                    self.assertTrue(tool.name.startswith('aeg_'))
                    self.assertNotIn('token', tool.input_schema['properties'])
                return envelope(await client.call_tool('aeg_context', {'request_id':'mcp-context'}))
        self.assertEqual(asyncio.run(run())['result']['snapshot']['task_id'], 'native')
    def test_real_protocol_approval_retry(self):
        from mcp import Client
        args = {'tool_id':'research','arguments_json':'{"path":"/fixture/data","query":{}}','request_id':'mcp-native'}
        async def run():
            async with Client(build_server(self.client), raise_exceptions=True) as client:
                first = envelope(await client.call_tool('aeg_call_tool', args))
                self.assertEqual(first['error'], 'approval_required')
                self.broker.approve_tool(first['call_id'], reviewer='test-operator')
                for _ in range(2):
                    self.assertEqual(envelope(await client.call_tool('aeg_call_tool', args))['result']['state'], 'SUCCEEDED')
        asyncio.run(run()); self.assertEqual(len(self.hits), 1)
    def test_actual_stdio_subprocess_handshake(self):
        from mcp import Client, StdioServerParameters
        root = Path(__file__).resolve().parents[1]
        # Only the scoped token file is passed; never the protected state directory.
        params = StdioServerParameters(command=sys.executable, args=[
            '-m','agent_effect_gate.integrations.mcp','--socket',str(self.folder/'gate.sock'),
            '--token-file',str(self.token_file),'--broker-uid',str(os.geteuid())],
            env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'PYTHONPATH':str(root)})
        async def run():
            async with Client(params) as client:
                return envelope(await client.call_tool('aeg_context', {'request_id':'stdio'}))
        self.assertTrue(asyncio.run(run())['ok'])
