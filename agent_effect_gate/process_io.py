"""Bounded subprocess pipe I/O without preexec_fn or unbounded communicate buffers."""
from __future__ import annotations
import os
import selectors
import signal
import subprocess
import time


def capture(argv, payload=b'', *, timeout=10, max_output=262144, **kwargs):
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, close_fds=True, **kwargs)
    selector = selectors.DefaultSelector()
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    reason, offset, started = None, 0, time.monotonic()
    for stream, name in ((process.stdout,'stdout'), (process.stderr,'stderr')):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    os.set_blocking(process.stdin.fileno(), False)
    if payload:
        selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
    else:
        process.stdin.close()
    try:
        while selector.get_map():
            if time.monotonic() - started >= timeout:
                reason = 'timeout'; break
            for key, _ in selector.select(min(0.1, max(0.001, timeout - (time.monotonic()-started)))):
                stream, name = key.fileobj, key.data
                if name == 'stdin':
                    try:
                        offset += os.write(stream.fileno(), payload[offset:offset+8192])
                    except BrokenPipeError:
                        offset = len(payload)
                    except BlockingIOError:
                        continue
                    if offset >= len(payload):
                        selector.unregister(stream); stream.close()
                else:
                    try:
                        chunk = os.read(stream.fileno(), 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream); stream.close()
                        continue
                    available = max_output - sum(map(len, buffers.values()))
                    buffers[name].extend(chunk[:max(0, available)])
                    if len(chunk) > available:
                        reason = 'output_limit'; break
            if reason:
                break
        if reason:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            rc = process.wait(timeout=max(0.1, timeout - (time.monotonic()-started)))
        except subprocess.TimeoutExpired:
            reason = 'timeout'
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            rc = process.wait(timeout=3)
        return {'returncode': rc, 'stdout': bytes(buffers['stdout']), 'stderr': bytes(buffers['stderr']), 'stop_reason': reason}
    finally:
        if process.poll() is None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=3)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed: stream.close()
