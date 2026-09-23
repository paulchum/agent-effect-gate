"""Native OpenAI Agents SDK function tools (optional ``openai`` extra)."""
from __future__ import annotations
from ..client import GateClient
from .common import GateToolkit, ToolBundle


def build_tools(client: GateClient) -> ToolBundle:
    try:
        from agents import function_tool
    except ImportError:
        raise ImportError('Install and qualify OpenAI Agents in the framework environment; see docs/FRAMEWORKS.md') from None
    toolkit = GateToolkit(client)
    # Broker decisions are JSON results. Unexpected host errors must propagate,
    # rather than being turned into provider-default messages containing secrets.
    tools = tuple(function_tool(function, failure_error_function=None, strict_mode=True)
                  for function in toolkit.async_functions())
    return ToolBundle(tools, toolkit)
