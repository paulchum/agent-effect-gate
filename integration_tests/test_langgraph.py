import asyncio
import json
from fixture import NativeBase
from agent_effect_gate.integrations.langgraph import build_tool_node


class LangGraph(NativeBase):
    def graph(self):
        from langgraph.graph import StateGraph, MessagesState, START, END
        node, bundle = build_tool_node(self.client)
        graph = StateGraph(MessagesState)
        graph.add_node('tools', node)
        graph.add_edge(START, 'tools'); graph.add_edge('tools', END)
        return graph.compile(), bundle
    def test_actual_compiled_graph_executes_gated_tool(self):
        from langchain_core.messages import AIMessage
        graph, bundle = self.graph()
        message = AIMessage(content='', tool_calls=[{'name':'aeg_context','args':{'request_id':'graph'},'id':'call-1','type':'tool_call'}])
        result = asyncio.run(graph.ainvoke({'messages':[message]}))
        envelope = json.loads(result['messages'][-1].content)
        self.assertTrue(envelope['ok'])
        self.assertEqual(envelope['result']['snapshot']['task_id'], 'native')
    def test_unknown_graph_tool_does_not_reach_broker(self):
        from langchain_core.messages import AIMessage
        graph, _ = self.graph()
        before = self.broker.store.db.execute('SELECT count(*) FROM tool_calls').fetchone()[0]
        message = AIMessage(content='', tool_calls=[{'name':'approve_tool','args':{'call_id':'fake'},'id':'call-2','type':'tool_call'}])
        result = graph.invoke({'messages':[message]})
        self.assertTrue(result['messages'][-1].content)
        after = self.broker.store.db.execute('SELECT count(*) FROM tool_calls').fetchone()[0]
        self.assertEqual(after, before); self.assertFalse(self.hits)
