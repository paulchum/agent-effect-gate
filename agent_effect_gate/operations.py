"""Operator-only health, consistent backup, and conservative disaster recovery."""
from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any

from .broker import Broker
from .codec import IntegrityError, authenticated, canonical, digest, exact_keys, identifier, loads, seal
from .configuration import validate_grants
from .policy import validate_policy
from .protected import (check_state, no_symlink_components, private_directory, private_file,
                        read_private, state_lease, sync_directory, write_private)
from .tool_config import load_tools
from ._version import __version__


def read_anchor(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    with path.open('rb') as stream:
        value = loads(stream.read(65_537), limit=65_536)
    # Accept both a raw head and the JSON output of init/audit/backup/restore.
    if isinstance(value, dict) and 'audit_head' in value:
        value = value['audit_head']
    exact_keys(value, {'seq', 'mac'})
    if type(value['seq']) is not int or value['seq'] < 0 or not isinstance(value['mac'], str) or not re.fullmatch('[0-9a-f]{64}', value['mac']):
        raise ValueError('Invalid external audit anchor')
    return value


def _hash_file(path: Path) -> str:
    private_file(path)
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _session_files(state: Path) -> list[Path]:
    private_directory(state / 'sessions')
    files = sorted((state / 'sessions').iterdir())
    for item in files:
        if item.suffix != '.token':
            raise ValueError('Unexpected sessions entry')
        identifier(item.stem)
        private_file(item)
    return files


def _checkpoint_files(state: Path) -> list[Path]:
    """Default local checkpoints only. External framework checkpoints stay external."""
    directory = state / 'runs'
    if not os.path.lexists(directory):
        return []
    private_directory(directory)
    files = []
    for item in sorted(directory.iterdir()):
        private_file(item)
        if item.name.endswith('.json.lock'):
            identifier(item.name[:-10])
            continue  # Inode-bound coordination must never be restored as data.
        if item.suffix != '.json':
            raise ValueError('Unexpected checkpoint directory entry')
        identifier(item.stem)
        from .models import RunCheckpoint
        RunCheckpoint(item).load()
        files.append(item)
    return files


def _copy_snapshot(source: Path, target: Path) -> None:
    """Copy immutable credentials/config plus SQLite's consistent backup image."""
    check_state(source)
    write_private(target / 'admin.key', read_private(source / 'admin.key', limit=4096))
    if os.path.lexists(source / 'tools.json'):
        write_private(target / 'tools.json', read_private(source / 'tools.json'))
    (target / 'sessions').mkdir(mode=0o700)
    for item in _session_files(source):
        write_private(target / 'sessions' / item.name, read_private(item, limit=4096))
    checkpoints = _checkpoint_files(source)
    if os.path.lexists(source / 'runs'):
        (target / 'runs').mkdir(mode=0o700)
        for item in checkpoints:
            write_private(target / 'runs' / item.name, read_private(item, limit=4_000_000))
        sync_directory(target / 'runs')
    write_private(target / 'state.sqlite', b'')
    # A connection context manager commits/rolls back; it does not close the
    # connection. Explicit closing also avoids leaking WAL locks during restore.
    with closing(sqlite3.connect((source / 'state.sqlite').as_uri() + '?mode=ro', uri=True)) as old:
        with closing(sqlite3.connect(target / 'state.sqlite')) as new:
            old.backup(new)
    sync_directory(target / 'sessions')


def _new_destination(destination: Path, source: Path) -> Path:
    destination = no_symlink_components(destination)
    if os.path.lexists(destination) or destination == source or source in destination.parents:
        raise ValueError('Use a new destination outside the source state')
    no_symlink_components(destination.parent)
    if not destination.parent.is_dir():
        raise ValueError('Destination parent must already exist')
    return destination


def _verify_snapshot(state: Path, anchor: dict[str, Any] | None) -> tuple[dict[str, Any], int]:
    broker = Broker(state / 'state.sqlite', read_private(state / 'admin.key', limit=4096), audit_anchor=anchor)
    try:
        if broker.store.db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise IntegrityError('SQLite integrity check failed')
        tasks = broker.store.db.execute('SELECT id FROM tasks').fetchall()
        for row in tasks:
            broker._policy(broker.store.db, row['id'])
        for item in _session_files(state):
            token = read_private(item, limit=4096).decode('ascii')
            row = broker.store.db.execute('SELECT agent FROM sessions WHERE token_hash=?', (digest(token.encode()),)).fetchone()
            if row is None or row['agent'] != item.stem:
                raise IntegrityError('Session file does not match database')
        return dict(broker.store._anchor), len(tasks)
    finally:
        broker.close()


def backup_state(state: Path, destination: Path, *, anchor: dict[str, Any] | None = None) -> dict[str, Any]:
    state = check_state(state)
    destination = _new_destination(destination, state)
    with state_lease(state, exclusive=True):
        scratch = Path(tempfile.mkdtemp(prefix='.aeg-backup-', dir=destination.parent))
        try:
            _copy_snapshot(state, scratch)
            head, tasks = _verify_snapshot(scratch, anchor)
            names = ['admin.key', 'state.sqlite']
            if (scratch / 'tools.json').exists():
                names.append('tools.json')
            names += [str(item.relative_to(scratch)) for item in _session_files(scratch)]
            names += [str(item.relative_to(scratch)) for item in _checkpoint_files(scratch)]
            manifest = {'format': 'aeg-backup-v1', 'package_version': __version__, 'audit_head': head,
                        'files': {name: _hash_file(scratch / name) for name in names}}
            signature = seal(read_private(scratch / 'admin.key', limit=4096), 'backup-v1', manifest)
            write_private(scratch / 'backup.json', canonical({'manifest': manifest, 'mac': signature}))
            with (scratch / 'state.sqlite').open('rb') as stream:
                os.fsync(stream.fileno())
            sync_directory(scratch)
            if os.path.lexists(destination):
                raise ValueError('Destination appeared during backup')
            os.rename(scratch, destination)
            sync_directory(destination.parent)
            return {'backed_up': True, 'audit_head': head, 'tasks': tasks,
                    'contains_secrets': True, 'encrypted': False, 'package_version': __version__,
                    'run_checkpoints': len(_checkpoint_files(destination)), 'external_checkpoints_included': False}
        except BaseException:
            shutil.rmtree(scratch, ignore_errors=True)
            raise


def _verify_backup(source: Path) -> dict[str, Any]:
    check_state(source)
    envelope = loads(read_private(source / 'backup.json'))
    exact_keys(envelope, {'manifest', 'mac'})
    manifest = envelope['manifest']
    exact_keys(manifest, {'format', 'package_version', 'audit_head', 'files'})
    if manifest['format'] != 'aeg-backup-v1' or not isinstance(manifest['files'], dict):
        raise ValueError('Unsupported backup format')
    if not authenticated(read_private(source / 'admin.key', limit=4096), 'backup-v1', manifest, envelope['mac']):
        raise IntegrityError('Backup manifest authentication failed')
    expected = {'admin.key', 'state.sqlite'}
    if (source / 'tools.json').exists():
        expected.add('tools.json')
    expected.update(str(item.relative_to(source)) for item in _session_files(source))
    expected.update(str(item.relative_to(source)) for item in _checkpoint_files(source))
    if set(manifest['files']) != expected:
        raise IntegrityError('Backup inventory mismatch')
    for name in expected:
        if _hash_file(source / name) != manifest['files'][name]:
            raise IntegrityError('Backup contents do not match manifest')
    # Reject extra files/sidecars rather than importing a snapshot with additional
    # unrecorded WAL contents. The lease file is runtime coordination, not data.
    allowed = {'admin.key', 'state.sqlite', 'sessions', 'tools.json', 'backup.json', '.operator.lock', 'runs'}
    if any(item.name not in allowed for item in source.iterdir()):
        raise IntegrityError('Unexpected backup contents')
    return manifest


def restore_state(source: Path, destination: Path, *, anchor: dict[str, Any], operator: str) -> dict[str, Any]:
    """Restore only into NEW state, require an external anchor, leave tasks stopped.

    The caller must stop/fence the old deployment. A local lease cannot prevent
    another machine from continuing to issue external effects.
    """
    identifier(operator)
    if anchor is None:
        raise ValueError('An externally retained audit anchor is required')
    source = check_state(source)
    destination = _new_destination(destination, source)
    with state_lease(source, exclusive=True):
        manifest = _verify_backup(source)
        scratch = Path(tempfile.mkdtemp(prefix='.aeg-restore-', dir=destination.parent))
        try:
            _copy_snapshot(source, scratch)
            head, tasks = _verify_snapshot(scratch, anchor)
            if head != manifest['audit_head']:
                raise IntegrityError('Backup journal does not match manifest')
            broker = Broker(scratch / 'state.sqlite', read_private(scratch / 'admin.key', limit=4096), audit_anchor=anchor)
            try:
                with broker.store.transaction() as db:
                    db.execute('UPDATE tasks SET suspended=1')
                    db.execute('DELETE FROM reviewer_sessions')
                    tools = db.execute("UPDATE tool_calls SET state='REVOKED' WHERE state IN ('PENDING','APPROVED')").rowcount
                    releases = db.execute("UPDATE proposals SET state='REVOKED' WHERE state IN ('PENDING','APPROVED')").rowcount
                    for row in db.execute('SELECT id FROM tasks').fetchall():
                        broker.store.append(db, row['id'], operator, 'state_restored_suspended',
                                            {'backup_head': head, 'pending_approvals_revoked': True})
                restored_head = dict(broker.store._anchor)
            finally:
                broker.close()
            with (scratch / 'state.sqlite').open('rb') as stream:
                os.fsync(stream.fileno())
            sync_directory(scratch)
            if os.path.lexists(destination):
                raise ValueError('Destination appeared during restore')
            os.rename(scratch, destination)
            sync_directory(destination.parent)
            return {'restored': True, 'audit_head': restored_head, 'backup_head': head,
                    'tasks': tasks, 'all_tasks_suspended': True,
                    'tool_approvals_revoked': tools, 'release_approvals_revoked': releases,
                    'reconciliation_required_before_resume': True,
                    'run_checkpoints': len(_checkpoint_files(destination))}
        except BaseException:
            shutil.rmtree(scratch, ignore_errors=True)
            raise


def doctor(state: Path, *, anchor: dict[str, Any] | None = None,
           production: bool = False, check_sandbox: bool = False) -> dict[str, Any]:
    """Readiness for an execution service, including credentials and isolation."""
    return _doctor(state, anchor=anchor, production=production, check_sandbox=check_sandbox)


def review_doctor(state: Path, *, anchor: dict[str, Any] | None = None,
                  production: bool = False, check_sandbox: bool = False) -> dict[str, Any]:
    """Control-plane readiness without execution adapters or their credentials."""
    return _doctor(state, anchor=anchor, production=production, review_only=True)


def _doctor(state: Path, *, anchor: dict[str, Any] | None = None,
           production: bool = False, check_sandbox: bool = False,
           review_only: bool = False) -> dict[str, Any]:
    state = check_state(state)
    checks: list[dict[str, Any]] = []
    def add(code: str, ok: bool, *, required: bool = True):
        checks.append({'code': code, 'ok': bool(ok), 'required': required})
    add('private_state_permissions', True)
    add('posix_host', os.name == 'posix')
    add('non_root_service_user', os.name == 'posix' and os.geteuid() != 0, required=production)
    add('external_anchor_supplied', anchor is not None, required=production)
    free = shutil.disk_usage(state).free
    add('free_disk_at_least_64_mib', free >= 64 * 1024 * 1024)
    broker = Broker(state / 'state.sqlite', read_private(state / 'admin.key', limit=4096), audit_anchor=anchor)
    try:
        add('audit_chain_verified', True)
        add('sqlite_quick_check', broker.store.db.execute('PRAGMA quick_check').fetchone()[0] == 'ok')
        specs = loads(read_private(state / 'tools.json')) if (state / 'tools.json').exists() else []
        tools = {} if review_only else load_tools(specs)
        add('review_without_effect_credentials' if review_only else 'tool_configuration_and_credentials', True)
        with broker.store.transaction() as db:
            rows = db.execute('SELECT id,suspended FROM tasks').fetchall()
            add('tasks_present', bool(rows))
            add('tasks_not_suspended', all(not row['suspended'] for row in rows), required=not review_only)
            for row in rows:
                _, policy = broker._policy(db, row['id'])
                if review_only:
                    validated = validate_policy(policy)
                    if production and validated['stage'] != 'deployment':
                        raise ValueError('Production policy must declare stage deployment')
                else:
                    validate_grants(validate_policy(policy), tools, production=production)
            add('task_policy_and_grants', True)
            active_files = set()
            for item in _session_files(state):
                token = read_private(item, limit=4096).decode('ascii')
                session = db.execute('SELECT task,agent,revoked FROM sessions WHERE token_hash=?', (digest(token.encode()),)).fetchone()
                if session is None or session['agent'] != item.stem:
                    raise IntegrityError('Session file does not match database')
                if not session['revoked']:
                    active_files.add((session['task'], session['agent']))
            expected = set()
            for row in rows:
                _, policy = broker._policy(db, row['id'])
                expected.update((row['id'], agent) for agent in policy['agents'])
            add('session_files_match_state', True)
            add('active_session_files_for_all_agents', expected <= active_files, required=not review_only)
            uncertain = db.execute("SELECT count(*) FROM tool_calls WHERE state IN ('DISPATCHING','UNKNOWN')").fetchone()[0]
            uncertain += db.execute("SELECT count(*) FROM proposals WHERE state IN ('DISPATCHING','UNKNOWN')").fetchone()[0]
            add('no_unreconciled_effects', uncertain == 0, required=not review_only)
        for name, tool in tools.items():
            if tool.manifest()['effect'] != 'local_code':
                continue
            if not check_sandbox:
                add('sandbox_' + name + '_runtime_not_checked', False, required=production)
            else:
                result = tool.invoke({'language': 'python', 'code': 'print("aeg-sandbox-ready")',
                                      'inputs': {}, 'input_sha256': {}, 'outputs': []}, 'operator-preflight')
                add('sandbox_' + name + '_runtime_probe', result.succeeded and result.text.strip() == 'aeg-sandbox-ready')
        return {'ready': all(c['ok'] for c in checks if c['required']), 'checks': checks,
                'package_version': __version__, 'python': platform.python_version(),
                'audit_head': dict(broker.store._anchor), 'free_disk_bytes': free,
                'uncertain_effects': uncertain, 'network_endpoints_probed': False, 'review_only': review_only,
                'scope': 'Local readiness checks; not a security certification or model integration test'}
    finally:
        broker.close()
