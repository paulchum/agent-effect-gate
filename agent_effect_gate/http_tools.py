"""Real, bounded HTTP adapters; no ambient proxies, cookies, redirects or model keys.

Even a GET discloses its path/query to the destination. Standing read grants are
therefore explicit egress authority, not a confidentiality guarantee.
"""
from __future__ import annotations
import base64
import http.client
import ipaddress
import re
import json
import sys
import threading
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit
from .codec import Rejected, canonical, digest, exact_keys, identifier, text
from .tool_types import ArtifactResolver, ToolResult
from .process_io import capture

def resolve_addresses(host: str, port: int, timeout: float) -> list[str]:
    """Bound DNS resolution in a killable, credential-free helper process."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    code = ('import json,socket,sys;'
            'print(json.dumps(list(dict.fromkeys(x[4][0] for x in '
            'socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)))))')
    result = capture([sys.executable, '-I', '-c', code, host, str(port)], timeout=timeout,
                     max_output=16384, env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
    if result['returncode'] != 0 or result['stop_reason']:
        raise OSError('DNS resolution failed or exceeded its deadline')
    addresses = json.loads(result['stdout'])
    if not isinstance(addresses, list) or not addresses or any(not isinstance(x,str) for x in addresses):
        raise OSError('Invalid resolver response')
    return addresses

class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, deadline):
        super().__init__(host, port, timeout=max(0.001,deadline-time.monotonic()))
        self.address, self.deadline, self.connected_socket = address, deadline, None
    def connect(self):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0: raise TimeoutError('HTTP deadline')
        self.sock = socket.create_connection((self.address, self.port), remaining)
        self.connected_socket = self.sock

class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, deadline, context):
        super().__init__(host, port, timeout=max(0.001,deadline-time.monotonic()), context=context)
        self.address, self.deadline, self.connected_socket = address, deadline, None
    def connect(self):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0: raise TimeoutError('HTTP deadline')
        sock = socket.create_connection((self.address, self.port), remaining)
        self.connected_socket = sock
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
            self.connected_socket = self.sock
            remaining = self.deadline-time.monotonic()
            if remaining <= 0: raise TimeoutError('HTTP deadline')
            self.sock.settimeout(remaining)
            self.sock.do_handshake()
        except BaseException:
            self.connected_socket.close()
            raise

@dataclass(frozen=True)
class HTTPTransport:
    """Host-specified exact origin. Loopback HTTP is an explicit local-test option."""
    origin: str
    credential: str | None = field(default=None, repr=False)
    allow_loopback: bool = False
    timeout_seconds: int = 10
    max_response_bytes: int = 65536
    ca_file: str | None = None

    def __post_init__(self):
        if type(self.allow_loopback) is not bool:
            raise ValueError('allow_loopback must be boolean')
        if not isinstance(self.origin, str) or not self.origin or any(ord(c) < 33 or ord(c) > 126 for c in self.origin):
            raise ValueError('Invalid HTTP origin')
        if self.ca_file is not None and not isinstance(self.ca_file, str):
            raise ValueError('Invalid CA file')
        u = urlsplit(self.origin)
        if u.scheme not in {'https','http'} or not u.hostname or u.username is not None or u.password is not None:
            raise ValueError('Use an exact HTTPS origin without credentials')
        if u.path not in {'','/'} or u.query or u.fragment or not u.hostname.isascii() or u.hostname.endswith('.'):
            raise ValueError('Invalid HTTP origin')
        try:
            loopback = ipaddress.ip_address(u.hostname).is_loopback
        except ValueError:
            loopback = False
        if self.allow_loopback and not loopback:
            raise ValueError('Loopback mode requires an exact loopback IP, not a hostname')
        if u.scheme != 'https' and not (self.allow_loopback and loopback):
            raise ValueError('Plain HTTP is only supported for explicit loopback tests')
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 30:
            raise ValueError('Invalid HTTP timeout')
        if type(self.max_response_bytes) is not int or not 1 <= self.max_response_bytes <= 131072:
            raise ValueError('Invalid HTTP response limit')
        if self.credential is not None and (not isinstance(self.credential, str) or
               not 20 <= len(self.credential) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in self.credential)):
            raise ValueError('Only a host-supplied, printable, high-entropy API token is supported')
        if u.port == 0:
            raise ValueError('Invalid HTTP port')
        _ = u.port  # Validate port before any model invocation.

    def manifest(self):
        # Host-private adapter input. The broker keys this binding before storage
        # and removes it from every agent-visible and reviewer-visible manifest.
        return {'origin': self.origin.rstrip('/'), 'loopback_test_mode': self.allow_loopback,
                'credential_binding': digest(self.credential.encode()) if self.credential else None,
                'timeout_seconds': self.timeout_seconds, 'max_response_bytes': self.max_response_bytes,
                'ca_binding': digest(Path(self.ca_file).read_bytes()) if self.ca_file else 'system-trust',
                'redirects': 'refused', 'proxy_environment': 'ignored', 'dns': 'validated-then-IP-pinned'}

    def _addresses(self):
        u = urlsplit(self.origin)
        # Resolution happens once. The connection dials one validated literal IP;
        # TLS still checks the configured hostname. No second DNS lookup on dial.
        addresses = resolve_addresses(u.hostname, u.port or (443 if u.scheme == 'https' else 80), self.timeout_seconds)
        if not addresses:
            raise OSError('No endpoint addresses')
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if self.allow_loopback:
                if not ip.is_loopback:
                    raise OSError('Non-loopback address refused')
            elif not ip.is_global:
                raise OSError('Non-public endpoint address refused')
        return addresses

    def request(self, method: str, target: str, call_id: str, payload: bytes | None = None,
                media_type: str = 'application/octet-stream', *, api_version: str | None = None) -> ToolResult:
        # prepare() creates the target; this defensive check also blocks request-line injection.
        if method not in {'GET','POST'} or not target.startswith('/') or target.startswith('//') or any(ord(c) < 33 or ord(c) > 126 for c in target):
            raise ValueError('Invalid prepared request')
        u = urlsplit(self.origin)
        port = u.port or (443 if u.scheme == 'https' else 80)
        started = time.monotonic()
        deadline = started + self.timeout_seconds
        address = self._addresses()[0]
        if time.monotonic() >= deadline:
            raise TimeoutError('HTTP deadline during DNS')
        context = ssl.create_default_context(cafile=self.ca_file) if u.scheme == 'https' else None
        conn = (_PinnedHTTPS(u.hostname, port, address, deadline, context) if context else
                _PinnedHTTP(u.hostname, port, address, deadline))
        headers = {'Accept': 'application/json,text/plain,*/*', 'Accept-Encoding': 'identity',
                   'User-Agent': 'agent-effect-gate/0.3', 'Connection': 'close'}
        if api_version is not None:
            if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', api_version):
                raise ValueError('Invalid API version')
            headers['X-GitHub-Api-Version'] = api_version
        if self.credential:
            headers['Authorization'] = 'Bearer ' + self.credential
        if method == 'POST':
            headers.update({'Content-Type': media_type, 'Idempotency-Key': call_id})
        def interrupt():
            sock = conn.connected_socket
            if sock is not None:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: sock.close()
                except OSError: pass
        # A total deadline also bounds slow-drip response HEADERS, not only body
        # chunks. The worker never retries the HTTP operation after interruption.
        timer = threading.Timer(max(0.001, deadline-time.monotonic()), interrupt)
        timer.daemon = True
        timer.start()
        try:
            conn.request(method, target, body=payload, headers=headers)
            response = conn.getresponse()
            if 300 <= response.status <= 399:
                return ToolResult({'http_status': response.status, 'error': 'redirect_refused'}, '', False)
            if response.getheader('Content-Encoding', 'identity').lower() not in {'','identity'}:
                return ToolResult({'http_status': response.status, 'error': 'encoded_response_refused'}, '', False)
            length = response.getheader('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) > self.max_response_bytes):
                return ToolResult({'http_status': response.status, 'error': 'response_too_large'}, '', False)
            body = bytearray()
            while True:
                remaining = self.timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('HTTP deadline')
                # getresponse can detach a Connection: close socket into its file.
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
                elif response.fp is not None:
                    raw = getattr(response.fp, 'raw', None)
                    sock = getattr(raw, '_sock', None)
                    if sock is not None:
                        sock.settimeout(remaining)
                chunk = response.read1(min(8192, self.max_response_bytes - len(body) + 1))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > self.max_response_bytes:
                    return ToolResult({'http_status': response.status, 'error': 'response_too_large'}, '', False)
            if length is not None and len(body) != int(length):
                return ToolResult({'http_status': response.status, 'error': 'truncated_response'}, '', False)
            decoded = bytes(body).decode('utf-8', errors='replace')
            content_type = response.getheader('Content-Type', '')[:200]
            if self.credential:
                decoded = decoded.replace(self.credential, '[REDACTED_BROKER_CREDENTIAL]')
                content_type = content_type.replace(self.credential, '[REDACTED_BROKER_CREDENTIAL]')
            data = {'http_status': response.status, 'body': decoded,
                    'content_type': content_type,
                    'origin': self.origin.rstrip('/'), 'response_bytes': len(body)}
            return ToolResult(data, decoded, 200 <= response.status < 300)
        finally:
            timer.cancel()
            conn.close()


def _path(value: Any) -> str:
    value = text(value, 1000)
    if not re.fullmatch(r'/[A-Za-z0-9/_~.\-]*', value) or '//' in value or any(x in {'.','..'} for x in value.split('/')):
        raise Rejected('path_not_allowed')
    return value

@dataclass(frozen=True)
class HTTPRead:
    transport: HTTPTransport
    path_prefix: str = '/'
    query_keys: tuple[str, ...] = ()

    def __post_init__(self):
        _path(self.path_prefix)
        for k in self.query_keys:
            identifier(k)
        object.__setattr__(self, 'query_keys', tuple(self.query_keys))

    def manifest(self):
        return {'adapter': 'http-read-v1', 'effect': 'network_read',
                'transport': self.transport.manifest(), 'path_prefix': self.path_prefix,
                'query_keys': list(self.query_keys),
                'arguments': {'path': 'absolute path under the configured prefix',
                              'query': 'object of allowed keys to strings; these strings leave the task'}}

    def prepare(self, arguments: dict[str, Any], artifact: ArtifactResolver):
        exact_keys(arguments, {'path','query'})
        path = _path(arguments['path'])
        prefix = self.path_prefix.rstrip('/')
        if prefix and path != prefix and not path.startswith(prefix + '/'):
            raise Rejected('path_not_allowed')
        q = arguments['query']
        if not isinstance(q, dict) or not q.keys() <= set(self.query_keys):
            raise Rejected('query_not_allowed')
        for value in q.values():
            text(value, 512)
        query = urlencode(sorted(q.items()))
        target = path + ('?' + query if query else '')
        if len(target) > 8192:
            raise Rejected('tool_request_too_large')
        return {'method': 'GET', 'target': target}

    def invoke(self, prepared, call_id):
        return self.transport.request('GET', prepared['target'], call_id)

@dataclass(frozen=True)
class HTTPUpload:
    """POST exact artifact bytes to a host-fixed endpoint, with per-call approval."""
    transport: HTTPTransport
    path: str

    def __post_init__(self):
        _path(self.path)

    def manifest(self):
        return {'adapter': 'http-upload-v1', 'effect': 'network_write', 'transport': self.transport.manifest(),
                'path': self.path, 'arguments': {'artifact_id': 'accessible task artifact; exact bytes are reviewed'}}

    def prepare(self, arguments, artifact):
        exact_keys(arguments, {'artifact_id'})
        payload, media_type, sha = artifact(identifier(arguments['artifact_id']))
        return {'method': 'POST', 'target': self.path, 'artifact_id': arguments['artifact_id'],
                'media_type': media_type, 'payload_sha256': sha, 'payload_b64': base64.b64encode(payload).decode()}

    def invoke(self, prepared, call_id):
        payload = base64.b64decode(prepared['payload_b64'], validate=True)
        if digest(payload) != prepared['payload_sha256']:
            raise ValueError('Upload bytes mismatch')
        return self.transport.request('POST', prepared['target'], call_id, payload, prepared['media_type'])

@dataclass(frozen=True)
class GitHubCodeSearch:
    """Search code in an operator-authorized repository, not the whole public index.

    GitHub's code-search endpoint requires a suitable authorized token. The agent
    cannot provide one, use a discovered token, or create credentials.
    """
    repositories: tuple[str, ...]
    transport: HTTPTransport = field(default_factory=lambda: HTTPTransport('https://api.github.com'))

    def __post_init__(self):
        object.__setattr__(self, 'repositories', tuple(self.repositories))
        if not self.repositories or len(self.repositories) > 50:
            raise ValueError('Configure at least one authorized repository')
        for repo in self.repositories:
            if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
                raise ValueError('Invalid repository scope')

    def manifest(self):
        return {'adapter': 'github-code-search-v1', 'effect': 'network_read',
                'transport': self.transport.manifest(), 'repositories': list(self.repositories), 'api_version': '2022-11-28',
                'arguments': {'repository': 'one configured repository', 'terms': '1–8 literal search terms',
                              'per_page': 'integer 1–30'}}

    def prepare(self, arguments, artifact):
        exact_keys(arguments, {'repository','terms','per_page'})
        if arguments['repository'] not in self.repositories:
            raise Rejected('repository_not_allowed')
        terms = arguments['terms']
        if not isinstance(terms, list) or not 1 <= len(terms) <= 8:
            raise Rejected('invalid_search_terms')
        for term in terms:
            if not isinstance(term, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,80}', term):
                raise Rejected('invalid_search_terms')
        page = arguments['per_page']
        if type(page) is not int or not 1 <= page <= 30:
            raise Rejected('invalid_page_size')
        # No model-supplied qualifiers, OR operators, scopes, headers or URLs.
        q = 'repo:' + arguments['repository'] + ' ' + ' '.join('"' + t + '"' for t in terms)
        return {'method': 'GET', 'target': '/search/code?' + urlencode({'q': q, 'per_page': page})}

    def invoke(self, prepared, call_id):
        return self.transport.request('GET', prepared['target'], call_id, api_version='2022-11-28')
