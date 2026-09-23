"""Transactional local state and a keyed, tamper-evident event journal.

The database and key belong to the trusted broker, never to an agent sandbox.
An externally retained journal head is required to detect complete rollback.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .protected import no_symlink_components, private_directory, private_file
from .tool_gate import TOOL_SCHEMA
from .reviewer_auth import SCHEMA as REVIEWER_SCHEMA
from .codec import IntegrityError, authenticated, canonical, loads, seal

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit(
 seq INTEGER PRIMARY KEY, timestamp REAL NOT NULL, task TEXT NOT NULL,
 agent TEXT NOT NULL, kind TEXT NOT NULL, details TEXT NOT NULL,
 previous TEXT NOT NULL, mac TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
 BEGIN SELECT RAISE(ABORT, 'audit is append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
 BEGIN SELECT RAISE(ABORT, 'audit is append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_sequence BEFORE INSERT ON audit
 WHEN NEW.seq != coalesce((SELECT max(seq) FROM audit),0)+1
 BEGIN SELECT RAISE(ABORT, 'audit sequence must append'); END;
CREATE TABLE IF NOT EXISTS tasks(
 id TEXT PRIMARY KEY, tenant TEXT NOT NULL, policy TEXT NOT NULL, version INTEGER NOT NULL,
 policy_mac TEXT NOT NULL, suspended INTEGER NOT NULL DEFAULT 0,
 requests INTEGER NOT NULL DEFAULT 0, denials INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY, task TEXT NOT NULL, agent TEXT NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(task) REFERENCES tasks(id));
CREATE TABLE IF NOT EXISTS sources(
 task TEXT NOT NULL, id TEXT NOT NULL, version TEXT NOT NULL, document TEXT NOT NULL,
 metadata TEXT NOT NULL, sha256 TEXT NOT NULL, mac TEXT NOT NULL,
 PRIMARY KEY(task,id,version), FOREIGN KEY(task) REFERENCES tasks(id));
CREATE TRIGGER IF NOT EXISTS sources_no_update BEFORE UPDATE ON sources
 BEGIN SELECT RAISE(ABORT, 'source is immutable'); END;
CREATE TRIGGER IF NOT EXISTS sources_no_delete BEFORE DELETE ON sources
 BEGIN SELECT RAISE(ABORT, 'source is immutable'); END;
CREATE TABLE IF NOT EXISTS artifacts(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, owner TEXT NOT NULL, media_type TEXT NOT NULL,
 payload BLOB NOT NULL, sha256 TEXT NOT NULL, mac TEXT NOT NULL,
 FOREIGN KEY(task) REFERENCES tasks(id));
CREATE TRIGGER IF NOT EXISTS artifacts_no_update BEFORE UPDATE ON artifacts
 BEGIN SELECT RAISE(ABORT, 'artifact is immutable'); END;
CREATE TRIGGER IF NOT EXISTS artifacts_no_delete BEFORE DELETE ON artifacts
 BEGIN SELECT RAISE(ABORT, 'artifact is immutable'); END;
CREATE TABLE IF NOT EXISTS artifact_access(
 artifact TEXT NOT NULL, agent TEXT NOT NULL, PRIMARY KEY(artifact,agent),
 FOREIGN KEY(artifact) REFERENCES artifacts(id));
CREATE TABLE IF NOT EXISTS messages(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL,
 content TEXT NOT NULL, timestamp REAL NOT NULL);
CREATE TABLE IF NOT EXISTS proposals(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, agent TEXT NOT NULL, artifact TEXT NOT NULL,
 destination TEXT NOT NULL, policy_version INTEGER NOT NULL, payload_sha256 TEXT NOT NULL,
 binding_mac TEXT NOT NULL, destination_manifest TEXT NOT NULL, state TEXT NOT NULL, approver TEXT, expires_at REAL, approval_mac TEXT,
 receipt TEXT, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS requests(
 task TEXT NOT NULL, agent TEXT NOT NULL, id TEXT NOT NULL, request_sha256 TEXT NOT NULL,
 response TEXT NOT NULL, PRIMARY KEY(task,agent,id));
CREATE TABLE IF NOT EXISTS read_request_hashes(
 task TEXT NOT NULL, agent TEXT NOT NULL, id TEXT NOT NULL, request_sha256 TEXT NOT NULL,
 PRIMARY KEY(task,agent,id), FOREIGN KEY(task) REFERENCES tasks(id));
CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, code TEXT NOT NULL, severity TEXT NOT NULL,
 first_seen REAL NOT NULL, last_seen REAL NOT NULL, occurrences INTEGER NOT NULL,
 first_event INTEGER NOT NULL, last_event INTEGER NOT NULL, status TEXT NOT NULL,
 track TEXT, owner TEXT, due_at REAL, third_party TEXT NOT NULL DEFAULT 'unknown',
 review TEXT, public_report TEXT, UNIQUE(task,code));
CREATE INDEX IF NOT EXISTS artifacts_task ON artifacts(task,owner);
CREATE INDEX IF NOT EXISTS messages_task_recipient ON messages(task,recipient,timestamp,id);
CREATE INDEX IF NOT EXISTS proposals_task ON proposals(task,created_at,id);
CREATE INDEX IF NOT EXISTS audit_task ON audit(task,seq);
"""


class StoreBusy(RuntimeError):
    """Transient SQLite contention, not evidence of corrupted storage."""


def _is_busy(exc: sqlite3.Error) -> bool:
    return (getattr(exc, 'sqlite_errorcode', 0) & 0xff) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


class Store:
    def __init__(self, path: str | Path, key: bytes, clock: Callable[[], float] = time.time,
                 anchor: dict[str, Any] | None = None):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Supply at least 32 random key bytes from the trusted host")
        self.key, self.clock = key, clock
        self.lock = threading.RLock()
        self.path = str(path)
        if self.path != ":memory:":
            p = no_symlink_components(Path(path))
            self.path = str(p)
            p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            private_directory(p.parent)
            for suffix in ("", "-wal", "-shm", "-journal"):
                candidate = Path(str(p) + suffix)
                if os.path.lexists(candidate):
                    try:
                        private_file(candidate)
                    except FileNotFoundError:
                        if not suffix:
                            raise
            if not p.exists():
                fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=10)
        try:
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript(SCHEMA + TOOL_SCHEMA + REVIEWER_SCHEMA)
            self.verification_stats = {"full_scans": 0, "full_rows": 0, "tail_rows": 0}
            # WAL readers do not exclude the running broker's writer. Never
            # upgrade this snapshot to a writer: commit, then verify its suffix.
            self.db.execute("BEGIN")
            verified_schema = self.db.execute("PRAGMA schema_version").fetchone()[0]
            self._anchor = self.verify(anchor)
            self.db.execute("COMMIT")
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("PRAGMA schema_version").fetchone()[0] != verified_schema:
                raise IntegrityError("Schema changed during startup verification; reopen")
            self._anchor = self._verify_tail(self._anchor)
            self._migrate_read_accounting()
            self._migrate_capability_accounting()
            self._migrate_live_cache()
            self._anchor = self._verify_tail(self._anchor)
            self._schema_version = self.db.execute("PRAGMA schema_version").fetchone()[0]
            self.db.execute("COMMIT")
        except BaseException:
            self.db.close()
            raise

    def _migrate_read_accounting(self) -> None:
        """One-time authenticated stored-schema normalization. Never rewrite historical audit rows.

        Old read cache entries are identifiable from authenticated allowed events.
        Move their request hashes, discard response bodies, and refund the old
        UNIQUE-read action charges. Historical read attempts consume the new quota.
        VACUUM is deliberately a separate, quiesced operator operation.
        """
        db = self.db
        if db.execute("SELECT 1 FROM schema_migrations WHERE version='read-quotas-v1'").fetchone():
            return
        columns = {row[1] for row in db.execute('PRAGMA table_info(tasks)')}
        if 'read_requests' not in columns:
            db.execute('ALTER TABLE tasks ADD COLUMN read_requests INTEGER NOT NULL DEFAULT 0')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='usage'").fetchone():
            # separate-counter already separated reads from actions. Do not refund actions
            # a second time or forget pre-upgrade read identities/counters.
            db.execute('UPDATE tasks SET read_requests=max(read_requests,coalesce('
                       '(SELECT reads FROM usage WHERE usage.task=tasks.id),0))')
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='read_receipts'").fetchone():
                db.execute('INSERT OR IGNORE INTO read_request_hashes SELECT task,agent,id,request_sha256 FROM read_receipts')
            db.execute("INSERT INTO schema_migrations VALUES('read-quotas-v1',?)", (self.clock(),))
            if db.execute('SELECT 1 FROM tasks LIMIT 1').fetchone():
                self.append(db, 'system', 'operator', 'read_accounting_migrated',
                            {'source': 'separate_counter-accounting', 'action_charges_refunded': 0})
            return
        reads = {'context', 'answer', 'inbox', 'read_artifact', 'resolve_field',
                 'list_tools', 'read_observation'}
        db.execute('CREATE TEMP TABLE legacy_reads(task TEXT,agent TEXT,sha TEXT,PRIMARY KEY(task,agent,sha))')
        counts = {}
        for row in db.execute("SELECT task,agent,details FROM audit WHERE kind='action_allowed'"):
            details = loads(row['details'])
            if details.get('operation') in reads and details.get('request_sha256'):
                db.execute('INSERT OR IGNORE INTO legacy_reads VALUES(?,?,?)',
                           (row['task'], row['agent'], details['request_sha256']))
                counts[row['task']] = counts.get(row['task'], 0) + 1
        moved = {}
        for row in db.execute('SELECT r.* FROM requests r JOIN legacy_reads l ON '
                              'r.task=l.task AND r.agent=l.agent AND r.request_sha256=l.sha').fetchall():
            db.execute('INSERT OR IGNORE INTO read_request_hashes VALUES(?,?,?,?)',
                       (row['task'], row['agent'], row['id'], row['request_sha256']))
            db.execute('DELETE FROM requests WHERE task=? AND agent=? AND id=?',
                       (row['task'], row['agent'], row['id']))
            moved[row['task']] = moved.get(row['task'], 0) + 1
        for task_id, attempts in counts.items():
            db.execute('UPDATE tasks SET requests=max(0,requests-?),read_requests=? WHERE id=?',
                       (moved.get(task_id, 0), attempts, task_id))
        db.execute('DROP TABLE legacy_reads')
        db.execute("INSERT INTO schema_migrations VALUES('read-quotas-v1',?)", (self.clock(),))
        if db.execute('SELECT 1 FROM tasks LIMIT 1').fetchone():
            self.append(db, 'system', 'operator', 'read_accounting_migrated',
                        {'read_bodies_removed': sum(moved.values()), 'read_attempts': sum(counts.values())})

    def _migrate_capability_accounting(self) -> None:
        """One-time conservative import. Never rewrite the signed policy or audit."""
        db = self.db
        if 'retry_requests' not in {row[1] for row in db.execute('PRAGMA table_info(tasks)')}:
            db.execute('ALTER TABLE tasks ADD COLUMN retry_requests INTEGER NOT NULL DEFAULT 0')
        if db.execute("SELECT 1 FROM schema_migrations WHERE version='capability-quotas-v1'").fetchone():
            return
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'usage' in tables:
            db.execute('UPDATE tasks SET retry_requests=max(retry_requests,coalesce('
                       '(SELECT retries FROM usage WHERE usage.task=tasks.id),0))')
        # Old human-auth sessions are NOT valid in the capability reviewer system.
        # Re-provision explicit task-scoped reviewers; never auto-promote viewers.
        if 'human_sessions' in tables:
            db.execute('DELETE FROM human_sessions')
        if 'human_users' in tables:
            db.execute('UPDATE human_users SET enabled=0')
        db.execute("INSERT INTO schema_migrations VALUES('capability-quotas-v1',?)", (self.clock(),))
        if db.execute('SELECT 1 FROM tasks LIMIT 1').fetchone():
            self.append(db, 'system', 'operator', 'capability_accounting_migrated',
                        {'retry_quota': 'independent', 'legacy_human_sessions_revoked': 'human_sessions' in tables})

    def _migrate_live_cache(self) -> None:
        """Remove legacy duplicated observations; retain request identities.

        Canonical observations stay in their authenticated immutable table.
        Operators may run compact later to reclaim unused database pages.
        """
        db = self.db
        if db.execute("SELECT 1 FROM schema_migrations WHERE version='compact-live-cache-v1'").fetchone():
            return
        changed = 0
        for row in db.execute('SELECT task,agent,id,response FROM requests'):
            response = loads(row['response'], limit=8_000_000)
            result = response.get('result') if isinstance(response, dict) else None
            if (isinstance(result, dict) and 'observation' in result and
                    isinstance(result.get('call_id'), str) and
                    db.execute('SELECT 1 FROM tool_calls WHERE id=? AND task=? AND agent=?',
                               (result['call_id'], row['task'], row['agent'])).fetchone()):
                result.pop('observation')
                db.execute('UPDATE requests SET response=? WHERE task=? AND agent=? AND id=?',
                           (canonical(response).decode(), row['task'], row['agent'], row['id']))
                changed += 1
        db.execute("INSERT INTO schema_migrations VALUES('compact-live-cache-v1',?)", (self.clock(),))
        if changed:
            self.append(db, 'system', 'operator', 'live_cache_compacted', {'entries': changed})

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                if self.db.execute("PRAGMA schema_version").fetchone()[0] != self._schema_version:
                    raise IntegrityError("Schema changed; reopen and fully verify before continuing")
                # Authenticate ONLY the suffix after our committed checkpoint. The
                # write transaction excludes races with other broker processes.
                start_head = self._verify_tail(self._anchor)
                yield self.db
                # Do not trust even locally appended records until the transaction
                # commits. A rollback must never advance the retained checkpoint.
                new_anchor = self._verify_tail(start_head)
                self.db.execute("COMMIT")
                self._anchor = new_anchor
            except BaseException as exc:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                if isinstance(exc, sqlite3.Error) and _is_busy(exc):
                    raise StoreBusy('storage_busy') from exc
                raise

    def append(self, db: sqlite3.Connection, task: str, agent: str, kind: str,
               details: dict[str, Any]) -> int:
        # Callers supply only stable codes, IDs and hashes, never model text or secrets.
        last = db.execute("SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        event = {"seq": last["seq"] + 1 if last else 1, "timestamp": self.clock(),
                 "task": task, "agent": agent, "kind": kind, "details": details,
                 "previous": last["mac"] if last else "0" * 64}
        mac = seal(self.key, "journal-v1", event)
        db.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?,?)",
                   (event["seq"], event["timestamp"], task, agent, kind,
                    canonical(details).decode(), event["previous"], mac))
        return event["seq"]

    def _event(self, row: sqlite3.Row) -> dict[str, Any]:
        from .codec import Rejected
        try:
            event = {k: row[k] for k in ("seq", "timestamp", "task", "agent", "kind", "previous")}
            event["details"] = loads(row["details"])
            if not authenticated(self.key, "journal-v1", event, row["mac"]):
                raise IntegrityError("Journal authentication failed")
            return event
        except Rejected as exc:
            raise IntegrityError("Invalid journal encoding") from exc

    def _verify_tail(self, anchor: dict[str, Any]) -> dict[str, Any]:
        """O(new entries), plus one indexed checkpoint lookup.

        Previously verified history is protected by SQLite's append-only and
        consecutive-insert triggers, a schema-change check, and protected storage.
        Arbitrary raw-file modification by a privileged attacker requires a full
        audit; incremental verification does not pretend to re-read old pages.
        """
        seq, previous = anchor["seq"], anchor["mac"]
        if seq:
            row = self.db.execute("SELECT * FROM audit WHERE seq=?", (seq,)).fetchone()
            if row is None or row["mac"] != previous:
                raise IntegrityError("Journal is behind or diverges from the retained checkpoint")
            self._event(row)
        for row in self.db.execute("SELECT * FROM audit WHERE seq>? ORDER BY seq", (seq,)):
            self.verification_stats["tail_rows"] += 1
            self._event(row)
            if row["seq"] != seq + 1 or row["previous"] != previous:
                raise IntegrityError("Journal chain discontinuity")
            seq, previous = row["seq"], row["mac"]
        return {"seq": seq, "mac": previous}

    def verify(self, anchor: dict[str, Any] | None = None) -> dict[str, Any]:
        """Explicit O(total history) full audit; never called by each request."""
        with self.lock:
            self.verification_stats["full_scans"] += 1
            previous, seq = "0" * 64, 0
            anchored = anchor is None or anchor == {"seq": 0, "mac": previous}
            for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
                self.verification_stats["full_rows"] += 1
                self._event(row)
                if row["seq"] != seq + 1 or row["previous"] != previous:
                    raise IntegrityError("Journal authentication failed")
                seq, previous = row["seq"], row["mac"]
                if anchor and anchor.get("seq") == seq and anchor.get("mac") == previous:
                    anchored = True
            if not anchored:
                raise IntegrityError("Journal is behind or diverges from the retained anchor")
            return {"seq": seq, "mac": previous}

    def close(self) -> None:
        with self.lock:
            self.db.close()
