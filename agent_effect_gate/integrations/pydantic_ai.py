"""Native Pydantic AI tools (optional ``pydantic`` extra)."""
from __future__ import annotations
from ..client import GateClient
from .common import GateToolkit, ToolBundle


def build_tools(client: GateClient) -> ToolBundle:
    try:
        from pydantic_ai import Tool
    except ImportError:
        raise ImportError('Install and qualify Pydantic AI in the framework environment; see docs/FRAMEWORKS.md') from None
    toolkit = GateToolkit(client)
    return ToolBundle(tuple(Tool(function, takes_ctx=False, name=function.__name__)
                            for function in toolkit.async_functions()), toolkit)
