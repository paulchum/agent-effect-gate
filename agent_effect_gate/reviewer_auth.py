"""Local reviewer accounts, task-scoped authorization and revocable web sessions.

Accounts are provisioned by the trusted service operator, not through the agent
plane. Passwords use salted scrypt (N=2**17,r=8,p=1). Browser tokens are random and
only their hashes are persisted. User grants and session records are authenticated
with the broker key. No password-reset email, public registration or implicit SSO.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass

from .codec import IntegrityError, authenticated, canonical, digest, identifier, loads, seal, text

SCHEMA = '''
CREATE TABLE IF NOT EXISTS reviewer_users(
 username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, task_scope TEXT NOT NULL,
 disabled INTEGER NOT NULL, epoch INTEGER NOT NULL, mac TEXT NOT NULL,
 failures INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS reviewer_sessions(
 token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL,
 created_at REAL NOT NULL, expires_at REAL NOT NULL, last_seen REAL NOT NULL,
 epoch INTEGER NOT NULL, mac TEXT NOT NULL,
 FOREIGN KEY(username) REFERENCES reviewer_users(username));
CREATE INDEX IF NOT EXISTS reviewer_sessions_user ON reviewer_sessions(username,created_at);
'''
SESSION_SECONDS = 8 * 3600
IDLE_SECONDS = 30 * 60


class AuthError(Exception):
    pass


def password_hash(password: str, salt: bytes | None = None) -> str:
    text(password, 1024)
    salt = salt or secrets.token_bytes(16)
    value = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**17, r=8, p=1,
                           maxmem=256 * 1024 * 1024, dklen=32)
    return 'scrypt-v1$' + salt.hex() + '$' + value.hex()


def verify_password(password: str, encoded: str) -> bool:
    try:
        kind, salt, expected = encoded.split('$')
        if kind != 'scrypt-v1' or len(salt) != 32 or len(expected) != 64:
            raise ValueError('Invalid stored hash')
        actual = password_hash(password, bytes.fromhex(salt)).rsplit('$', 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        raise IntegrityError('Invalid stored reviewer credential') from None


@dataclass(frozen=True)
class Reviewer:
    username: str
    tasks: tuple[str, ...]
    token_hash: str
    csrf: str


class ReviewerAuth:
    def __init__(self, store):
        self.store = store
        self._limiter_lock = threading.Lock()
        self._tokens, self._refilled = 10.0, time.monotonic()
        self._hash_slots = threading.BoundedSemaphore(2)

    @staticmethod
    def _user_value(row):
        return {k: row[k] for k in ('username', 'password_hash', 'task_scope', 'disabled', 'epoch')}

    @staticmethod
    def _session_value(row):
        return {k: row[k] for k in ('token_hash', 'username', 'csrf', 'created_at', 'expires_at', 'last_seen', 'epoch')}

    def _user(self, db, username):
        row = db.execute('SELECT * FROM reviewer_users WHERE username=?', (username,)).fetchone()
        if row and not authenticated(self.store.key, 'reviewer-user-v1', self._user_value(row), row['mac']):
            raise IntegrityError('Reviewer account authentication failed')
        return row

    def set_user(self, username: str, password: str, tasks: list[str]) -> None:
        """Host-only create/reset. Resetting a password revokes every old session."""
        identifier(username)
        text(password, 1024)
        if len(password) < 16:
            raise ValueError('Use at least 16 password characters')
        if not isinstance(tasks, list) or not 1 <= len(tasks) <= 100 or len(set(tasks)) != len(tasks):
            raise ValueError('Explicit task scope is required')
        for task in tasks:
            identifier(task)
        encoded = password_hash(password)
        with self.store.transaction() as db:
            old = self._user(db, username)
            if old is None and db.execute('SELECT count(*) FROM reviewer_users').fetchone()[0] >= 64:
                raise ValueError('Reviewer account limit reached')
            for task in tasks:
                if not db.execute('SELECT 1 FROM tasks WHERE id=?', (task,)).fetchone():
                    raise ValueError('Reviewer task does not exist')
            value = {'username': username, 'password_hash': encoded, 'task_scope': canonical(sorted(tasks)).decode(),
                     'disabled': 0, 'epoch': old['epoch'] + 1 if old else 1}
            mac = seal(self.store.key, 'reviewer-user-v1', value)
            db.execute('INSERT INTO reviewer_users(username,password_hash,task_scope,disabled,epoch,mac) '
                       'VALUES(:username,:password_hash,:task_scope,:disabled,:epoch,:mac) '
                       'ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,task_scope=excluded.task_scope,'
                       'disabled=0,epoch=excluded.epoch,mac=excluded.mac,failures=0,locked_until=0', {**value, 'mac': mac})
            db.execute('DELETE FROM reviewer_sessions WHERE username=?', (username,))
            for task in tasks:
                self.store.append(db, task, 'operator', 'reviewer_account_provisioned', {'reviewer': username, 'reset': old is not None})

    def disable(self, username: str) -> None:
        identifier(username)
        with self.store.transaction() as db:
            row = self._user(db, username)
            if row is None:
                raise ValueError('Unknown reviewer')
            value = {**self._user_value(row), 'disabled': 1, 'epoch': row['epoch'] + 1}
            db.execute('UPDATE reviewer_users SET disabled=1,epoch=?,mac=? WHERE username=?',
                       (value['epoch'], seal(self.store.key, 'reviewer-user-v1', value), username))
            db.execute('DELETE FROM reviewer_sessions WHERE username=?', (username,))
            for task in loads(row['task_scope']):
                self.store.append(db, task, 'operator', 'reviewer_account_disabled', {'reviewer': username})

    def _admit_login(self):
        # Fixed-size process-wide limiter, not an unbounded attacker-keyed map.
        with self._limiter_lock:
            now = time.monotonic()
            self._tokens = min(10.0, self._tokens + (now - self._refilled) / 6)
            self._refilled = now
            if self._tokens < 1:
                raise AuthError('rate_limited')
            self._tokens -= 1
        if not self._hash_slots.acquire(blocking=False):
            raise AuthError('rate_limited')

    def login(self, username: str, password: str) -> tuple[str, Reviewer]:
        text(username, 80)
        text(password, 1024)
        self._admit_login()
        try:
            with self.store.transaction() as db:
                user = self._user(db, username)
                snapshot = dict(user) if user else None
            # Unknown users incur the same scrypt work as known users.
            encoded = snapshot['password_hash'] if snapshot else 'scrypt-v1$' + '00' * 16 + '$' + '00' * 32
            matches = verify_password(password, encoded)
        finally:
            self._hash_slots.release()
        with self.store.transaction() as db:
            user = self._user(db, username)
            now = self.store.clock()
            valid = (matches and user is not None and snapshot is not None and
                     user['epoch'] == snapshot['epoch'] and not user['disabled'] and user['locked_until'] <= now)
            if not valid:
                if user and not user['disabled'] and user['locked_until'] <= now:
                    failures = user['failures'] + 1
                    db.execute('UPDATE reviewer_users SET failures=?,locked_until=? WHERE username=?',
                               (0 if failures >= 5 else failures, now + 900 if failures >= 5 else 0, username))
                # Commit bounded failure counters without generating an audit
                # entry or persisting attacker-selected unknown usernames.
                result = None
            else:
                db.execute('UPDATE reviewer_users SET failures=0,locked_until=0 WHERE username=?', (username,))
                db.execute('DELETE FROM reviewer_sessions WHERE expires_at<=? OR last_seen<=?', (now, now - IDLE_SECONDS))
                old = db.execute('SELECT token_hash FROM reviewer_sessions WHERE username=? '
                                 'ORDER BY created_at DESC,token_hash DESC', (username,)).fetchall()
                for row in old[3:]:
                    db.execute('DELETE FROM reviewer_sessions WHERE token_hash=?', (row['token_hash'],))
                token = secrets.token_urlsafe(32)
                value = {'token_hash': digest(token.encode()), 'username': username, 'csrf': secrets.token_urlsafe(32),
                         'created_at': now, 'expires_at': now + SESSION_SECONDS, 'last_seen': now, 'epoch': user['epoch']}
                db.execute('INSERT INTO reviewer_sessions VALUES(:token_hash,:username,:csrf,:created_at,:expires_at,'
                           ':last_seen,:epoch,:mac)', {**value, 'mac': seal(self.store.key, 'reviewer-session-v1', value)})
                for task in loads(user['task_scope']):
                    self.store.append(db, task, username, 'reviewer_login', {})
                result = (token, Reviewer(username, tuple(loads(user['task_scope'])), value['token_hash'], value['csrf']))
        if result is None:
            raise AuthError('not_authenticated')
        return result

    def authenticate(self, token: str | None) -> Reviewer:
        if not isinstance(token, str) or not 40 <= len(token) <= 100:
            raise AuthError('not_authenticated')
        with self.store.transaction() as db:
            row = db.execute('SELECT * FROM reviewer_sessions WHERE token_hash=?', (digest(token.encode()),)).fetchone()
            if row is None:
                raise AuthError('not_authenticated')
            value = self._session_value(row)
            if not authenticated(self.store.key, 'reviewer-session-v1', value, row['mac']):
                raise IntegrityError('Reviewer session authentication failed')
            user = self._user(db, row['username'])
            now = self.store.clock()
            if (user is None or user['disabled'] or row['epoch'] != user['epoch'] or
                row['expires_at'] <= now or row['last_seen'] + IDLE_SECONDS <= now):
                raise AuthError('not_authenticated')
            if now - row['last_seen'] >= 60:
                value['last_seen'] = now
                db.execute('UPDATE reviewer_sessions SET last_seen=?,mac=? WHERE token_hash=?',
                           (now, seal(self.store.key, 'reviewer-session-v1', value), row['token_hash']))
            return Reviewer(user['username'], tuple(loads(user['task_scope'])), row['token_hash'], row['csrf'])

    def logout(self, reviewer: Reviewer) -> None:
        with self.store.transaction() as db:
            db.execute('DELETE FROM reviewer_sessions WHERE token_hash=?', (reviewer.token_hash,))
            for task in reviewer.tasks:
                self.store.append(db, task, reviewer.username, 'reviewer_logout', {})
