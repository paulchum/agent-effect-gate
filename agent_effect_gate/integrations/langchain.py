"""Native LangChain StructuredTool objects, also consumed by LangGraph ToolNode."""
from __future__ import annotations
from ..client import GateClient
from .common import GateToolkit, ToolBundle


def build_tools(client: GateClient) -> ToolBundle:
    try:
        from langchain_core.tools import StructuredTool
    except ImportError:
        raise ImportError('Install and qualify LangChain in the framework environment; see docs/FRAMEWORKS.md') from None
    toolkit = GateToolkit(client)
    tools = tuple(StructuredTool.from_function(func=sync, coroutine=async_fn,
                  name=sync.__name__, description=sync.__doc__ or '', infer_schema=True)
                  for sync, async_fn in zip(toolkit.functions(), toolkit.async_functions(), strict=True))
    return ToolBundle(tools, toolkit)
