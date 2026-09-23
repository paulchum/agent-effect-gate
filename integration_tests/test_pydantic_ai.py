import asyncio
import json
from fixture import NativeBase
from agent_effect_gate.integrations.pydantic_ai import build_tools


class PydanticAI(NativeBase):
    def test_real_agent_loop_submits_model_prose(self):
        from pydantic_ai import Agent, ModelResponse, TextPart, ToolCallPart, models
        from pydantic_ai.models.function import FunctionModel
        models.ALLOW_MODEL_REQUESTS = False
        bundle = build_tools(self.client)
        calls = []
        async def scripted_model(messages, info):
            calls.append(info)
            if len(calls) == 1:
                self.assertEqual(len(info.function_tools), 11)
                return ModelResponse(parts=[ToolCallPart('aeg_submit_answer', {
                    'text':'Authored by a scripted model through the real SDK',
                    'citations_json':'[]', 'limitations_json':'["Not a live-model evaluation"]',
                    'request_id':'pydantic-final'})])
            return ModelResponse(parts=[TextPart('Unaudited chat response: do not display this')])
        agent = Agent(FunctionModel(scripted_model), tools=list(bundle.tools))
        result = asyncio.run(agent.run('Write a final answer'))
        self.assertEqual(len(calls), 2)
        answer = bundle.answer(request_id='render')['result']['answer']
        self.assertNotEqual(answer['text'], result.output)
        self.assertIn('scripted model', answer['text'])
        self.assertFalse(answer['truthfulness_verified'])
    def test_actual_tool_function_and_schema(self):
        from pydantic_ai import Tool
        bundle = build_tools(self.client)
        self.assertEqual(len(bundle.tools), 11)
        for tool in bundle.tools: self.assertIsInstance(tool, Tool)
        tool = next(t for t in bundle.tools if t.name == 'aeg_context')
        self.assertTrue(json.loads(asyncio.run(tool.function(request_id='native')))['ok'])
