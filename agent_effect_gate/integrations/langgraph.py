"""An AEG-only ToolNode for a host-controlled LangGraph graph.

Other graph nodes and callbacks remain trusted application code. This does not
intercept unrelated nodes, tools, provider-side tools, or direct networking.
"""
from __future__ import annotations
from ..client import GateClient
from .langchain import build_tools


def build_tool_node(client: GateClient):
    try:
        from langgraph.prebuilt import ToolNode
    except ImportError:
        raise ImportError('Install and qualify LangGraph in the framework environment; see docs/FRAMEWORKS.md') from None
    bundle = build_tools(client)
    return ToolNode(list(bundle.tools), handle_tool_errors=False), bundle
