"""Actual broker and UNIX transport used by native SDK tests. No SDK doubles."""
from __future__ import annotations
import os
import secrets
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from agent_effect_gate import Broker
from agent_effect_gate.client import GateClient, UnixTransport
from agent_effect_gate.http_tools import HTTPTransport, HTTPRead
from agent_effect_gate.ipc import UnixGateServer


class NativeBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        self.hits = []
        hits = self.hits
        class Endpoint(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                hits.append(self.path)
                body = b'{"fixture":true,"units":27}'
                self.send_response(200); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.http_thread.start()
        transport = HTTPTransport(f'http://127.0.0.1:{self.http.server_port}', allow_loopback=True)
        self.broker = Broker(self.folder/'state.sqlite', secrets.token_bytes(32),
                             tools={'research': HTTPRead(transport, '/fixture', ())})
        self.token = self.broker.create_task('native', 'fixture', {
            'agents':['main'], 'answer_mode':'model', 'local_only':False,
            'max_denials':100,
            'tool_grants':{'research':{'approval':'required','max_calls':5}}
        })['main']
        self.ipc = UnixGateServer(self.folder/'gate.sock', self.broker).start()
        self.client = GateClient(UnixTransport(self.folder/'gate.sock', self.token))
        self.token_file = self.folder/'session.token'
        self.token_file.write_text(self.token); self.token_file.chmod(0o600)
    def tearDown(self):
        self.ipc.stop(); self.broker.close()
        self.http.shutdown(); self.http.server_close(); self.http_thread.join(2)
        self.tmp.cleanup()
