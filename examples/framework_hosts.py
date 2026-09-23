"""Host recipes. Imports are lazy; no live provider calls occur on import.

Call only from an authorized host with an explicitly configured model/provider.
The host must enforce model budgets, approval pauses and egress policy. These
recipes are not evidence that the uninstalled SDKs ran in the authoring container.
"""
from agent_effect_gate.client import GateClient
from agent_effect_gate.integrations.common import INSTRUCTIONS


async def run_openai(client: GateClient, model, prompt: str):
    from agents import Agent, Runner, set_tracing_disabled
    from agent_effect_gate.integrations.openai_agents import build_tools
    set_tracing_disabled(True)
    bundle=build_tools(client)
    agent=Agent(name='AEG scoped worker',model=model,instructions=INSTRUCTIONS,tools=list(bundle.tools))
    bundle.assert_inventory(agent.tools)
    await Runner.run(agent,prompt,max_turns=10)
    return await bundle.aanswer(request_id='host-render-openai')


async def run_langgraph(client: GateClient, model, prompt: str):
    from langchain_core.messages import HumanMessage, SystemMessage
    from langgraph.graph import StateGraph,MessagesState,START
    from langgraph.prebuilt import tools_condition
    from agent_effect_gate.integrations.langgraph import build_tool_node
    node,bundle=build_tool_node(client)
    scoped_model=model.bind_tools(list(bundle.tools))
    async def generate(state):
        return {'messages':[await scoped_model.ainvoke([SystemMessage(content=INSTRUCTIONS),*state['messages']])]}
    graph=StateGraph(MessagesState)
    graph.add_node('agent',generate);graph.add_node('tools',node)
    graph.add_edge(START,'agent');graph.add_conditional_edges('agent',tools_condition);graph.add_edge('tools','agent')
    await graph.compile().ainvoke({'messages':[HumanMessage(content=prompt)]},config={'recursion_limit':20})
    return await bundle.aanswer(request_id='host-render-langgraph')


async def run_pydantic(client: GateClient, model, prompt: str):
    from pydantic_ai import Agent
    from pydantic_ai.usage import UsageLimits
    from agent_effect_gate.integrations.pydantic_ai import build_tools
    bundle=build_tools(client)
    agent=Agent(model,instructions=INSTRUCTIONS,tools=list(bundle.tools))
    await agent.run(prompt,usage_limits=UsageLimits(request_limit=10))
    return await bundle.aanswer(request_id='host-render-pydantic')
