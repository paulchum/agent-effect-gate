"""Small ASGI reviewer application, served by Uvicorn (the optional review extra).

No permissive CORS, embedded credentials, active rendering of agent data, public
registration or agent execution endpoint. Deploy only on loopback or with TLS.
"""
from __future__ import annotations

import asyncio
import hmac
import re
import sqlite3
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .store import StoreBusy
from .codec import IntegrityError, Rejected, canonical, exact_keys, loads
from .reviewer_auth import AuthError, ReviewerAuth, SESSION_SECONDS
from .reviewer_service import ReviewerService

ASSETS = Path(__file__).with_name('web')
SECURITY_HEADERS = {
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer', 'cache-control': 'no-store',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
}


class WebError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class ReviewerApp:
    def __init__(self, broker, *, public_origin: str = 'http://127.0.0.1:8765'):
        url = urlsplit(public_origin)
        if (url.scheme not in {'http', 'https'} or not url.hostname or url.username is not None or
            url.password is not None or url.path or url.query or url.fragment or
            any(ord(c) < 33 or ord(c) > 126 for c in public_origin)):
            raise ValueError('Set an exact reviewer public origin without a path')
        if url.scheme == 'http' and url.hostname not in {'localhost', '127.0.0.1', '::1'}:
            raise ValueError('Non-loopback reviewer origins require HTTPS')
        if url.port == 0:
            raise ValueError('Invalid public port')
        self.broker, self.origin, self.host = broker, public_origin, url.netloc.lower()
        self.secure = url.scheme == 'https'
        self.cookie_name = '__Host-aeg_review' if self.secure else 'aeg_review_local'
        self.auth, self.service = ReviewerAuth(broker.store), ReviewerService(broker)

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            while True:
                message = await receive()
                if message['type'] == 'lifespan.startup':
                    await send({'type': 'lifespan.startup.complete'})
                elif message['type'] == 'lifespan.shutdown':
                    await send({'type': 'lifespan.shutdown.complete'})
                    return
        if scope['type'] != 'http':
            return
        headers = dict(SECURITY_HEADERS)
        if self.secure:
            headers['strict-transport-security'] = 'max-age=31536000'
        status, body = 200, b''
        try:
            values = {}
            for key, value in scope.get('headers', []):
                name = key.decode('latin-1').lower()
                if name in values and name in {'host', 'origin', 'cookie', 'content-length', 'content-type', 'x-csrf-token'}:
                    raise WebError(400, 'duplicate_header')
                values[name] = value.decode('latin-1')
            if values.get('host', '').lower() != self.host:
                raise WebError(403, 'host_not_allowed')
            origin = values.get('origin')
            if origin is not None and origin != self.origin:
                raise WebError(403, 'origin_not_allowed')
            method, path = scope['method'], scope['path']
            if method not in {'GET', 'POST'}:
                raise WebError(405, 'method_not_allowed')
            if self.broker._failed and path.startswith('/api/'):
                raise WebError(503, 'service_unavailable')
            payload = None
            if method == 'POST':
                if origin != self.origin:
                    raise WebError(403, 'origin_required')
                if values.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                    raise WebError(415, 'json_required')
                if 'content-length' in values:
                    if not values['content-length'].isascii() or not values['content-length'].isdecimal():
                        raise WebError(400, 'invalid_content_length')
                    if int(values['content-length']) > 8192:
                        raise WebError(413, 'body_too_large')
                payload = await asyncio.wait_for(self._body(receive), timeout=10)
            if method == 'GET' and path in {'/', '/app.js', '/app.css'}:
                file, mime = {'/': ('index.html', 'text/html; charset=utf-8'),
                              '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                              '/app.css': ('app.css', 'text/css; charset=utf-8')}[path]
                headers['content-type'] = mime
                body = (ASSETS / file).read_bytes()
            elif method == 'GET' and path == '/healthz':
                status = 503 if self.broker._failed else 200
                body = canonical({'ok': not self.broker._failed})
            elif method == 'POST' and path == '/api/login':
                exact_keys(payload, {'username', 'password'})
                token, reviewer = await asyncio.to_thread(self.auth.login, payload['username'], payload['password'])
                headers['set-cookie'] = self._cookie(token)
                body = canonical(self._session(reviewer))
            else:
                cookie = SimpleCookie()
                try:
                    cookie.load(values.get('cookie', ''))
                    morsel = cookie.get(self.cookie_name)
                    token = morsel.value if morsel else None
                except Exception:
                    raise WebError(401, 'not_authenticated') from None
                reviewer = await asyncio.to_thread(self.auth.authenticate, token)
                if method == 'POST' and not hmac.compare_digest(values.get('x-csrf-token', ''), reviewer.csrf):
                    raise WebError(403, 'csrf_required')
                if method == 'GET' and path == '/api/session':
                    body = canonical(self._session(reviewer))
                elif method == 'GET' and path == '/api/overview':
                    body = canonical(await asyncio.to_thread(self.service.overview, reviewer))
                elif method == 'GET' and path == '/api/queue':
                    if len(scope.get('query_string', b'')) > 1024:
                        raise WebError(400, 'invalid_query')
                    query = parse_qs(scope.get('query_string', b'').decode('ascii'), max_num_fields=2)
                    if set(query) - {'state', 'offset'} or any(len(v) != 1 for v in query.values()):
                        raise WebError(400, 'invalid_query')
                    body = canonical(await asyncio.to_thread(self.service.queue, reviewer,
                        query.get('state', ['PENDING'])[0], int(query.get('offset', ['0'])[0])))
                elif method == 'GET' and (match := re.fullmatch(r'/api/review/(tool|release)/([A-Za-z0-9][A-Za-z0-9_.-]{0,79})', path)):
                    body = canonical(await asyncio.to_thread(self.service.detail, reviewer, *match.groups()))
                elif method == 'POST' and path == '/api/decision':
                    exact_keys(payload, {'kind', 'id', 'decision', 'review_token'})
                    body = canonical(await asyncio.to_thread(self.service.decide, reviewer, payload['kind'], payload['id'],
                                                             payload['decision'], payload['review_token']))
                elif method == 'POST' and path == '/api/logout':
                    exact_keys(payload, set())
                    await asyncio.to_thread(self.auth.logout, reviewer)
                    headers['set-cookie'] = self._cookie('', max_age=0)
                    body = canonical({'ok': True})
                else:
                    raise WebError(404, 'not_found')
        except WebError as exc:
            status, body = exc.status, canonical({'ok': False, 'error': exc.code})
        except AuthError as exc:
            status = 429 if str(exc) == 'rate_limited' else 401
            if status == 429:
                headers['retry-after'] = '60'
            body = canonical({'ok': False, 'error': str(exc)})
        except Rejected as exc:
            code = str(exc)
            status = (404 if code in {'review_not_found', 'tool_call_not_found', 'proposal_not_found', 'artifact_not_found'}
                      else 409 if code in {'review_changed_refresh_required', 'approval_binding_changed', 'proposal_not_pending',
                                          'dispatch_already_started', 'task_suspended'} else 400)
            body = canonical({'ok': False, 'error': code})
        except asyncio.TimeoutError:
            status, body = 408, canonical({'ok': False, 'error': 'request_timeout'})
        except (ValueError, TypeError, UnicodeError):
            status, body = 400, canonical({'ok': False, 'error': 'invalid_request'})
        except StoreBusy:
            status, body = 503, canonical({'ok': False, 'error': 'broker_busy', 'retryable': True})
        except (IntegrityError, sqlite3.Error, OSError):
            self.broker._failed = True
            status, body = 503, canonical({'ok': False, 'error': 'service_unavailable'})
        except Exception:
            status, body = 503, canonical({'ok': False, 'error': 'service_unavailable'})
        headers.setdefault('content-type', 'application/json; charset=utf-8')
        headers['content-length'] = str(len(body))
        await send({'type': 'http.response.start', 'status': status,
                    'headers': [(k.encode(), v.encode()) for k, v in headers.items()]})
        await send({'type': 'http.response.body', 'body': body})

    async def _body(self, receive):
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                raise WebError(400, 'client_disconnected')
            body.extend(message.get('body', b''))
            if len(body) > 8192:
                raise WebError(413, 'body_too_large')
            if not message.get('more_body', False):
                return loads(bytes(body), limit=8192)

    @staticmethod
    def _session(reviewer):
        return {'username': reviewer.username, 'tasks': list(reviewer.tasks), 'csrf': reviewer.csrf}

    def _cookie(self, token, max_age=SESSION_SECONDS):
        return (f'{self.cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}'
                + ('; Secure' if self.secure else ''))
