"""Scoped stdio MCP: built-in server and optional native SDK backend.

The MCP process has a scoped token, never an admin key or general network tools.
Do not enable another MCP server or client-side shell as an unreviewed bypass.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path

from .. import __version__
from ..client import GateClient
from .common import GateToolkit, INSTRUCTIONS


def build_server(client: GateClient):
    try:
        from mcp.server import MCPServer
    except ImportError:
        raise ImportError('Install and qualify the MCP SDK dependency in the framework environment; see docs/FRAMEWORKS.md') from None
    server = MCPServer('Agent Effect Gate', instructions=INSTRUCTIONS, version=__version__)
    toolkit = GateToolkit(client)
    for function in toolkit.async_functions():
        server.add_tool(function, name=function.__name__, description=function.__doc__ or '')
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='agent-effect-gate-mcp', description='AEG scoped MCP stdio server; no control plane')
    parser.add_argument('--backend', choices=['builtin', 'sdk'], default='builtin', help='Dependency-free stdio protocol or optional native SDK backend')
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--broker-uid', type=int, default=os.geteuid())
    args = parser.parse_args(argv)
    client = GateClient.unix(args.socket, args.token_file, expected_server_uid=args.broker_uid)
    # Do not print/log token files or model arguments to the MCP stdout channel.
    if args.backend == 'sdk':
        build_server(client).run(transport='stdio')
    else:
        from ..mcp_server import ScopedMCPServer, serve_mcp
        import signal
        import threading
        stop = threading.Event()
        previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            serve_mcp(ScopedMCPServer(client), stop)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
