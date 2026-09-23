"""Linux local data-plane transport. Never exports control-plane methods.

Deploy the broker under a DIFFERENT OS user from agent-generated code. The
framework host receives only a scoped bearer token and a socket, not admin.key.
All framing is bounded; authenticated requests still go through Broker.handle.
"""
from __future__ import annotations

import math
import os
import socket
import socketserver
import stat
import struct
import threading
import time
from pathlib import Path
from typing import Any

from .codec import MAX_WIRE_BYTES, Rejected, canonical, exact_keys, loads

MAX_REQUEST_FRAME = MAX_WIRE_BYTES + 1024
MAX_RESPONSE_FRAME = 16_000_000
PROTOCOL = 'aeg-local-v1'


class TransportError(RuntimeError):
    """An IPC result is unknown. Never infer that an external effect did not occur."""

    def __init__(self, code: str = 'gate_transport_unavailable') -> None:
        super().__init__(code)
        self.code = code


def _limit(value: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0.05 <= value <= 300:
        raise ValueError('Transport timeout must be finite and between 0.05 and 300 seconds')
    return float(value)


def peer_uid(connection: socket.socket) -> int:
    """Kernel-derived identity; fail closed on unsupported systems."""
    if not hasattr(socket, 'SO_PEERCRED'):
        raise TransportError('peer_identity_unavailable')
    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return uid


def _read_exact(connection: socket.socket, size: int, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('IPC deadline')
        connection.settimeout(remaining)
        part = connection.recv(min(65536, size - len(chunks)))
        if not part:
            raise TransportError('gate_transport_incomplete')
        chunks.extend(part)
    return bytes(chunks)


def receive_frame(connection: socket.socket, limit: int, deadline: float) -> bytes:
    size = struct.unpack('!I', _read_exact(connection, 4, deadline))[0]
    if not 1 <= size <= limit:
        raise TransportError('gate_frame_too_large')
    return _read_exact(connection, size, deadline)


def send_frame(connection: socket.socket, payload: bytes, limit: int, deadline: float) -> None:
    if not 1 <= len(payload) <= limit:
        raise TransportError('gate_frame_too_large')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('IPC deadline')
    connection.settimeout(remaining)
    connection.sendall(struct.pack('!I', len(payload)) + payload)


def _safe_socket_directory(path: Path, owner: int | None = None) -> None:
    parent = path.parent
    if not parent.is_absolute() or parent.is_symlink():
        raise ValueError('Use an absolute, non-symlink socket directory')
    st = parent.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
        raise ValueError('Socket directory must not be group/world writable')
    if owner is not None and st.st_uid != owner:
        raise ValueError('Socket directory must belong to the broker OS user')


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        try:
            if peer_uid(self.request) not in server.allowed_uids:
                response = {'ok': False, 'error': 'unauthorized_peer'}
            else:
                raw = receive_frame(self.request, MAX_REQUEST_FRAME, time.monotonic() + server.io_timeout)
                envelope = loads(raw, limit=MAX_REQUEST_FRAME)
                exact_keys(envelope, {'protocol', 'token', 'request'})
                if envelope['protocol'] != PROTOCOL:
                    raise Rejected('unsupported_transport_protocol')
                # Credentials cannot be model arguments. The host client binds them.
                response = server.broker.handle(envelope['token'], envelope['request'])
            raw_response = canonical(response)
            if len(raw_response) > MAX_RESPONSE_FRAME:
                raw_response = canonical({'ok': False, 'error': 'gate_response_too_large',
                                          'delivery_outcome': 'unknown'})
            send_frame(self.request, raw_response, MAX_RESPONSE_FRAME, time.monotonic() + server.io_timeout)
        except (Rejected, TransportError, OSError, ValueError):
            # Fixed error only; no token, model text, paths, or exception text in logs.
            try:
                send_frame(self.request, canonical({'ok': False, 'error': 'invalid_transport_request',
                                                    'delivery_outcome': 'unknown'}),
                           MAX_RESPONSE_FRAME, time.monotonic() + 0.1)
            except (OSError, TransportError):
                pass


class UnixGateServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Bounded local IPC server. One request/connection; persistent broker process.

    ``allowed_uids`` is an OS admission list, NOT a task identity. The broker also
    validates the scoped session token for every request. 0660 permits access via
    an operator-provisioned shared group; the parent must stay non-writable to it.
    """
    daemon_threads = False
    block_on_close = True
    request_queue_size = 32

    def __init__(self, path: str | Path, broker: Any, *, allowed_uids: set[int] | None = None,
                 max_workers: int = 16, io_timeout: float = 10, socket_mode: int = 0o600) -> None:
        if not hasattr(socket, 'SO_PEERCRED'):
            raise ValueError('This transport requires Linux SO_PEERCRED')
        if type(max_workers) is not int or not 1 <= max_workers <= 128:
            raise ValueError('max_workers must be between 1 and 128')
        if socket_mode not in (0o600, 0o660):
            raise ValueError('Only private or operator-managed group socket access is permitted')
        self.path = Path(path)
        _safe_socket_directory(self.path, os.geteuid())
        if os.path.lexists(self.path):
            raise ValueError('Refusing to replace an existing socket or file')
        self.allowed_uids = frozenset({os.geteuid()} if allowed_uids is None else allowed_uids)
        if not self.allowed_uids or any(type(uid) is not int or uid < 0 for uid in self.allowed_uids):
            raise ValueError('Supply a nonempty list of numeric OS user IDs')
        self.io_timeout = _limit(io_timeout)
        self.broker = broker
        self._slots = threading.BoundedSemaphore(max_workers)
        self._owned_inode = None
        self._serving_thread = None
        super().__init__(str(self.path), _Handler, bind_and_activate=False)
        try:
            self.server_bind()
            os.chmod(self.path, socket_mode)
            st = self.path.lstat()
            self._owned_inode = (st.st_dev, st.st_ino)
            self.server_activate()
        except BaseException:
            self.server_close()
            raise

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            # Do not create unbounded threads or queue requests with unknown effects.
            try:
                send_frame(request, canonical({'ok': False, 'error': 'gate_busy', 'retryable': True}),
                           MAX_RESPONSE_FRAME, time.monotonic() + 0.1)
            except (OSError, TransportError):
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: socket.socket, client_address: Any) -> None:
        # socketserver's default prints exception tracebacks. They can contain data.
        return

    def start(self) -> 'UnixGateServer':
        """Convenience for trusted host embedding and tests; CLI runs in foreground."""
        if self._serving_thread is not None:
            raise ValueError('Server already started')
        self._serving_thread = threading.Thread(target=self.serve_forever, kwargs={'poll_interval': 0.05},
                                                name='aeg-ipc', daemon=True)
        self._serving_thread.start()
        return self

    def stop(self) -> None:
        if self._serving_thread is not None:
            self.shutdown()
            self._serving_thread.join()
            self._serving_thread = None
        self.server_close()

    def server_close(self) -> None:
        super().server_close()
        try:
            st = self.path.lstat()
            if self._owned_inode == (st.st_dev, st.st_ino) and stat.S_ISSOCK(st.st_mode):
                self.path.unlink()
        except FileNotFoundError:
            pass
