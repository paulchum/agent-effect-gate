"""Sync/async SDK client. No shell, credentials for external services, or approvals.

Transport failures are never automatically retried. A caller may recover by using
EXACTLY the same logical request ID and arguments against the same durable broker.
"""
from __future__ import annotations

import asyncio
import os
import socket
import stat
import time
from pathlib import Path
from typing import Any, Protocol

from .codec import Rejected, canonical, digest, identifier, loads
from .ipc import (MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME, PROTOCOL, TransportError,
                  _limit, _safe_socket_directory, peer_uid, receive_frame, send_frame)


class GateTransport(Protocol):
    def exchange(self, request: dict[str, Any]) -> dict[str, Any]: ...


class UnixTransport:
    """Agent-side connection to a fixed local broker; kernel-check its OS identity."""
    def __init__(self, socket_path: str | Path, token: str, *, expected_server_uid: int | None = None,
                 timeout: float = 120) -> None:
        self.socket_path = Path(socket_path)
        if not self.socket_path.is_absolute():
            raise ValueError('Socket path must be absolute')
        if not isinstance(token, str) or not 20 <= len(token) <= 200 or not token.isascii():
            raise ValueError('Invalid scoped session token')
        self._token = token
        self.expected_server_uid = os.geteuid() if expected_server_uid is None else expected_server_uid
        if type(self.expected_server_uid) is not int or self.expected_server_uid < 0:
            raise ValueError('Invalid broker OS identity')
        self.timeout = _limit(timeout)

    def __repr__(self) -> str:
        return 'UnixTransport(token=<redacted>, local_broker=True)'

    def exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        raw = canonical({'protocol': PROTOCOL, 'token': self._token, 'request': request})
        if len(raw) > MAX_REQUEST_FRAME:
            raise TransportError('gate_request_too_large')
        deadline = time.monotonic() + self.timeout
        try:
            _safe_socket_directory(self.socket_path, self.expected_server_uid)
            st = self.socket_path.lstat()
            if not stat.S_ISSOCK(st.st_mode) or st.st_mode & 0o007 or st.st_uid != self.expected_server_uid:
                raise TransportError('gate_socket_identity_mismatch')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(str(self.socket_path))
                if peer_uid(connection) != self.expected_server_uid:
                    raise TransportError('gate_peer_identity_mismatch')
                send_frame(connection, raw, MAX_REQUEST_FRAME, deadline)
                response = loads(receive_frame(connection, MAX_RESPONSE_FRAME, deadline), limit=MAX_RESPONSE_FRAME)
            if not isinstance(response, dict) or type(response.get('ok')) is not bool:
                raise TransportError('gate_invalid_response')
            return response
        except (OSError, ValueError, Rejected) as exc:
            raise TransportError() from None


def read_session_token(path: str | Path) -> str:
    """Read a privately provisioned token, not the broker's admin key.

    Uses a no-follow open and descriptor checks rather than check-then-open.
    """
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.geteuid():
            raise ValueError('Token must be a regular private file owned by the framework OS user')
        if not 20 <= st.st_size <= 202:
            raise ValueError('Invalid scoped token file size')
        value = os.read(fd, 203).decode('ascii').strip()
        if not 20 <= len(value) <= 200:
            raise ValueError('Invalid scoped token file')
        return value
    finally:
        os.close(fd)


class GateClient:
    """Provider-neutral client; all integration adapters use these exact semantics."""
    def __init__(self, transport: GateTransport) -> None:
        self._transport = transport

    @classmethod
    def unix(cls, socket_path: str | Path, token_file: str | Path, *, expected_server_uid: int | None = None,
             timeout: float = 120) -> 'GateClient':
        return cls(UnixTransport(socket_path, read_session_token(token_file),
                                 expected_server_uid=expected_server_uid, timeout=timeout))

    def request(self, operation: str, arguments: dict[str, Any], *, request_id: str) -> dict[str, Any]:
        identifier(request_id)
        request = loads(canonical({'request_id': request_id, 'operation': operation, 'arguments': arguments}))
        return self._transport.exchange(request)

    def view(self, operation: str) -> dict[str, Any]:
        """Scoped framework reads always spend broker read quota."""
        if operation not in {'context', 'answer'}:
            raise ValueError('Only context and answer views are supported')
        import secrets
        return self.request(operation, {}, request_id='view_' + secrets.token_hex(16))

    @staticmethod
    def _phase_id(request_id: str, phase: str) -> str:
        identifier(request_id)
        return 'sdk_' + digest(canonical(['aeg-sdk-v1', request_id, phase]))

    def call_tool(self, tool_id: str, arguments: dict[str, Any], *, request_id: str) -> dict[str, Any]:
        """Propose then execute with deterministic IDs across restarts/approval waits.

        Never hashes the arguments into the request ID: changed arguments under the
        same logical ID MUST conflict, not silently become a second external action.
        """
        proposal = self.request('propose_tool', {'tool_id': tool_id, 'arguments': arguments},
                                request_id=self._phase_id(request_id, 'proposal'))
        if not proposal['ok']:
            return proposal
        call_id = proposal['result']['call_id']
        result = self.request('execute_tool', {'call_id': call_id},
                              request_id=self._phase_id(request_id, 'execution'))
        return {**result, 'call_id': call_id, 'logical_request_id': request_id}

    async def arequest(self, operation: str, arguments: dict[str, Any], *, request_id: str) -> dict[str, Any]:
        # Cancelling this await does NOT cancel an already dispatched external effect.
        # No retry loop; caller recovers with the same request identity.
        return await asyncio.to_thread(self.request, operation, arguments, request_id=request_id)

    async def acall_tool(self, tool_id: str, arguments: dict[str, Any], *, request_id: str) -> dict[str, Any]:
        return await asyncio.to_thread(self.call_tool, tool_id, arguments, request_id=request_id)
