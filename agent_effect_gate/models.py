"""Checkpointed scoped-client runtime, consolidated with the strict model connector.

A checkpoint is private conversation data, NOT broker authority. The exact next
broker envelope is saved before dispatch. An uncertain result never triggers a
fresh model proposal or an automatic second effect identity. Recovery is explicit.
"""
from __future__ import annotations

import os
import secrets
import stat
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from .codec import Rejected, canonical, exact_keys, identifier, loads
from .ipc import TransportError
from .model_connector import OpenAIResponsesAdapter
from .protected import no_symlink_components, private_directory, private_file, read_private, sync_directory

# Compatibility import name; constructor follows the customer connector and
# REQUIRES allow_provider_egress=True. The old free-prose adapter is not shipped.
ResponsesAdapter = OpenAIResponsesAdapter
MAX_CHECKPOINT_BYTES = 4_000_000
CHECKPOINT_FORMAT = 'aeg-model-run-v2'
QUOTA_ERRORS = frozenset({'request_budget_exhausted', 'read_budget_exhausted',
                          'retry_budget_exhausted', 'tool_plan_quota_exceeded',
                          'tool_budget_exhausted', 'artifact_quota_exceeded',
                          'message_quota_exceeded', 'observation_quota_exceeded'})


def _action(value: Any) -> dict[str, Any]:
    action = loads(value) if isinstance(value, (str, bytes)) else loads(canonical(value))
    exact_keys(action, {'request_id', 'operation', 'arguments'})
    identifier(action['request_id'])
    if not isinstance(action['operation'], str) or not isinstance(action['arguments'], dict):
        raise Rejected('invalid_action_envelope')
    return action


class RunCheckpoint:
    """Atomic, bounded, private recovery record with a single-writer run lease.

    Parent must be owned by the current host user and mode 0700. A mode-0600
    sidecar lock is retained deliberately. Do not put checkpoints in an agent
    workspace or share one checkpoint between independent conversations.
    """
    def __init__(self, path: str | Path):
        self.path = no_symlink_components(Path(path))
        self._check_path()

    def _check_path(self) -> None:
        private_directory(self.path.parent)
        no_symlink_components(self.path)
        if os.path.lexists(self.path):
            private_file(self.path)

    @contextmanager
    def lease(self):
        """Hold across load, provider call, broker dispatch and final save."""
        import fcntl
        self._check_path()
        path = self.path.with_name(self.path.name + '.lock')
        no_symlink_components(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_NONBLOCK', 0), 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise ValueError('Unsafe checkpoint lease')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Rejected('checkpoint_busy') from None
            yield
        finally:
            os.close(fd)

    def load(self) -> dict[str, Any] | None:
        self._check_path()
        try:
            value = loads(read_private(self.path, limit=MAX_CHECKPOINT_BYTES), limit=MAX_CHECKPOINT_BYTES)
        except FileNotFoundError:
            return None
        exact_keys(value, {'format', 'scope', 'adapter', 'pending_request', 'last_result', 'complete'})
        if value['format'] != CHECKPOINT_FORMAT:
            raise Rejected('checkpoint_format_requires_manual_migration')
        exact_keys(value['scope'], {'task_id', 'agent', 'scope_id'})
        identifier(value['scope']['task_id']); identifier(value['scope']['agent'])
        scope_id = value['scope']['scope_id']
        if not isinstance(scope_id, str) or len(scope_id) != 64 or any(c not in '0123456789abcdef' for c in scope_id):
            raise Rejected('invalid_checkpoint_scope')
        if (type(value['complete']) is not bool or not isinstance(value['adapter'], dict) or
                (value['last_result'] is not None and not isinstance(value['last_result'], dict))):
            raise Rejected('invalid_checkpoint')
        if value['pending_request'] is not None:
            _action(value['pending_request'])
        if value['complete'] and value['pending_request'] is not None:
            raise Rejected('invalid_checkpoint')
        return value

    def save(self, value: dict[str, Any]) -> None:
        raw = canonical(value)
        if len(raw) > MAX_CHECKPOINT_BYTES:
            raise Rejected('checkpoint_too_large')
        self._check_path()
        temporary = self.path.with_name('.' + self.path.name + '.' + secrets.token_hex(8))
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_path()
            os.replace(temporary, self.path)
            sync_directory(self.path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def _view(client: Any, operation: str) -> dict[str, Any]:
    if callable(getattr(client, 'view', None)):
        return client.view(operation)
    return client.request(operation, {}, request_id='view_' + secrets.token_hex(16))


class _AdapterFailed(Exception):
    pass


def run_client(adapter: Any, client: Any, *, max_steps: int = 20,
               checkpoint: RunCheckpoint | None = None, resume: bool = False) -> dict[str, Any]:
    """Run against a scoped client, preserving the exact pending request on pause.

    max_steps bounds each explicit invocation. Task-wide broker quotas persist
    across invocations. Agent-side snapshots remain metered; the in-process
    trusted runtime uses a separate host-only view implementation.
    """
    if type(max_steps) is not int or not 1 <= max_steps <= 1000:
        raise ValueError('max_steps must be between 1 and 1000')
    if type(resume) is not bool:
        raise ValueError('resume must be boolean')
    if resume and checkpoint is None:
        raise ValueError('resume requires a checkpoint')
    if checkpoint and not all(callable(getattr(adapter, name, None)) for name in ('export_state', 'import_state')):
        raise ValueError('Checkpointed adapters must implement export_state and import_state')
    pending = None
    last = None
    scope = None

    def persist(*, complete: bool = False) -> None:
        if checkpoint is not None:
            checkpoint.save({'format': CHECKPOINT_FORMAT, 'scope': scope, 'adapter': adapter.export_state(),
                             'pending_request': pending, 'last_result': last, 'complete': complete})

    try:
        with checkpoint.lease() if checkpoint else nullcontext():
            saved = checkpoint.load() if checkpoint else None
            if saved is not None and not resume:
                raise Rejected('existing_checkpoint_requires_resume')
            if resume and saved is None:
                raise Rejected('checkpoint_not_found')
            last = saved['last_result'] if saved else None
            pending = saved['pending_request'] if saved else None
            imported = False
            for _ in range(max_steps):
                view = _view(client, 'context')
                if not view.get('ok'):
                    return view
                context = view['result']['snapshot']
                scope = {'task_id': context['task_id'], 'agent': context['agent'], 'scope_id': context.get('scope_id')}
                if checkpoint and not isinstance(scope['scope_id'], str):
                    raise Rejected('broker_scope_binding_required')
                if saved and saved['scope'] != scope:
                    raise Rejected('checkpoint_scope_mismatch')
                if saved and not imported:
                    adapter.import_state(saved['adapter'])
                    imported = True
                if saved and saved['complete']:
                    return _view(client, 'answer')
                if context['control']['suspended']:
                    return {'ok': False, 'error': 'task_suspended', 'status': 'paused'}
                # Existing pending requests may already have spent their action
                # reservation, so resume them even when no NEW action is allowed.
                if pending is None:
                    if context['control']['budgets']['actions']['remaining'] == 0:
                        return {'ok': False, 'error': 'request_budget_exhausted', 'status': 'paused'}
                    try:
                        proposed = adapter.propose(loads(canonical(context), limit=8_000_000),
                                                   loads(canonical(last), limit=8_000_000) if last is not None else None)
                    except Exception:
                        raise _AdapterFailed() from None
                    pending = _action(proposed)
                # Crash between this fsynced write and response receipt leaves
                # the original request identity available for explicit recovery.
                persist()
                last = client.request(pending['operation'], pending['arguments'], request_id=pending['request_id'])
                if not isinstance(last, dict) or type(last.get('ok')) is not bool:
                    raise TransportError('gate_invalid_response')
                error = last.get('error')
                if error in {'approval_required', 'approval_expired'}:
                    persist()
                    return {**last, 'status': 'awaiting_approval', 'pending_request': pending,
                            'resume_available': checkpoint is not None}
                if (pending['operation'] in {'execute_tool', 'execute_release'} and
                        last.get('result', {}).get('state') in {'UNKNOWN', 'DISPATCHING'}):
                    persist()
                    return {**last, 'status': 'awaiting_reconciliation', 'pending_request': pending,
                            'recovery': 'Inspect the original effect. Do not create a new request ID.'}
                if (last.get('action_execution_stopped') or last.get('delivery_outcome') == 'unknown' or
                        error in {'broker_stopped', 'broker_busy', 'gate_busy', 'gate_response_too_large', 'invalid_transport_request'}):
                    persist()
                    return {**last, 'status': 'paused', 'pending_request': pending}
                if error in QUOTA_ERRORS:
                    persist()
                    return {**last, 'status': 'paused', 'pending_request': pending}
                operation = pending['operation']
                pending = None
                complete = bool(last.get('ok') and operation in {'submit_answer', 'answer'} and
                                last.get('result', {}).get('answer', {}).get('status') != 'awaiting_model_answer')
                persist(complete=complete)
                if complete:
                    return _view(client, 'answer')
            return {'ok': False, 'error': 'runtime_step_budget_exhausted', 'status': 'paused',
                    'resume_available': checkpoint is not None}
    except TransportError:
        return {'ok': False, 'error': 'broker_connection_failed', 'delivery_outcome': 'unknown',
                'pending_request': pending, 'resume_available': checkpoint is not None,
                'recovery': 'Inspect broker state and resume only the original saved request.'}
    except _AdapterFailed:
        return {'ok': False, 'error': 'model_adapter_failed', 'status': 'failed'}
    except Rejected as exc:
        return {'ok': False, 'error': str(exc), 'status': 'paused'}
    except Exception:
        return {'ok': False, 'error': 'model_or_checkpoint_failed', 'status': 'failed',
                'recovery': 'Inspect broker state and resume only the original checkpoint.'}
