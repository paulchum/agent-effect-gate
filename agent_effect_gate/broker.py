"""The trusted broker. Only ``handle`` is exposed on the agent data plane.

All other public methods are control-plane operations for authenticated host code.
Importing this library into an interpreter running model-generated Python is NOT
an isolation boundary. Use the JSON-only process interface or a trusted harness.
"""
from __future__ import annotations

import base64
import binascii
import math
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .codec import (MAX_WIRE_BYTES, IntegrityError, Rejected, authenticated, canonical,
                    digest, exact_keys, identifier, loads, seal, text)
from .policy import evaluate, validate_policy
from .store import Store, StoreBusy
from .tool_gate import ToolGate, TOOL_READS, TOOL_SCHEMAS, TERMINAL, public_manifest
from .tool_types import ToolAdapter

# Public summaries are fixed strings, never copies of model input or exception text.
NOTICES = {
    "tool_not_allowed": "A proposed tool was outside this task's delegated capabilities.",
    "tool_unavailable": "An authorized tool adapter was unavailable.",
    "tool_budget_exhausted": "The authorized call budget for a tool was exhausted.",
    "tool_failed": "A tool returned a non-success result; that result is not a completion certificate.",
    "tool_outcome_unknown": "The outcome of a tool attempt was not confirmed. It was not automatically repeated.",
    "citation_quote_mismatch": "A proposed citation did not match the captured tool output.",
    "observation_not_found": "A proposed observation was missing or outside this agent's accessible scope.",
    "argument_egress_not_authorized": "Automatic disclosure of model-selected request arguments was not authorized.",
    "writes_require_exact_approval": "An external write requires approval of its exact destination and bytes.",
    "path_not_allowed": "A proposed path was outside the configured tool scope.",
    "repository_not_allowed": "A proposed repository was outside the configured search scope.",
    "invalid_schema": "An action contained fields that this interface does not authorize.",
    "unknown_operation": "An unsupported operation was blocked.",
    "local_only": "An attempted external release was blocked by the local-only contract.",
    "destination_not_allowed": "An external destination was not authorized for this task.",
    "destination_unavailable": "The approved destination adapter is not available.",
    "channel_not_allowed": "An attempted communication channel was not authorized.",
    "artifact_not_found": "An artifact was absent or not accessible to this agent.",
    "artifact_not_owned": "Only an artifact's author may request a release or grant access.",
    "source_missing": "A required source version is unavailable; no replacement values were invented.",
    "source_digest_mismatch": "The available source did not match the required content digest.",
    "source_field_missing": "A required field was missing from the specified source.",
    "source_type_mismatch": "The specified source could not support the requested transformation.",
    "empty_mean": "An average could not be computed from an empty series.",
    "non_finite_result": "A calculation did not produce a finite result.",
    "approval_required": "An external release was not dispatched because independent approval was absent.",
    "approval_expired": "An external release approval expired before dispatch.",
    "approval_binding_changed": "An approval no longer matches the current action, policy, or destination.",
    "release_outcome_unknown": "A release was attempted, but its external outcome is not confirmed; it will not be retried automatically.",
    "task_suspended": "This task has been suspended; further effectful actions are blocked.",
    "request_budget_exhausted": "The task's action budget has been exhausted.",
    "read_budget_exhausted": "The task's read quota has been exhausted.",
    "retry_budget_exhausted": "The task's retry quota has been exhausted.",
    "tool_plan_quota_exceeded": "The task's prepared-request storage quota has been exhausted.",
    "request_id_conflict": "A request identifier was reused for different action content.",
    "artifact_quota_exceeded": "The private artifact storage limit was reached.",
    "message_quota_exceeded": "The private collaboration message limit was reached.",
    "operator_flag": "An operator flagged an additional concern for investigation.",
    "runtime_step_budget_exhausted": "The model's proposal budget ended; this is not a claim that the entire task was completed.",
    "model_adapter_failed": "The model adapter failed; no unsupported final text was forwarded.",
}

LIVE_OPERATIONS = {"execute_release", "execute_tool", "submit_answer"}
READ_OPERATIONS = {"context", "answer", "inbox", "read_artifact", "resolve_field"}
OPERATIONS = READ_OPERATIONS | {"put_artifact", "share_artifact", "send_message",
                               "propose_release", "execute_release"}
SCHEMAS = {
    "context": set(), "answer": set(), "inbox": set(),
    "resolve_field": {"field_id"}, "put_artifact": {"media_type", "data_b64"},
    "read_artifact": {"artifact_id"}, "share_artifact": {"artifact_id", "recipient"},
    "send_message": {"recipient", "text"},
    "propose_release": {"artifact_id", "destination_id"},
    "execute_release": {"proposal_id"},
}
READ_OPERATIONS |= TOOL_READS
OPERATIONS |= set(TOOL_SCHEMAS)
SCHEMAS.update(TOOL_SCHEMAS)

MEDIA_TYPES = {"text/plain", "application/json", "application/octet-stream", "image/png",
               "image/jpeg", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


@dataclass(frozen=True)
class Sink:
    """An operator-owned, narrowly scoped effect adapter.

    ``send`` must honor the manifest's fixed audience and use the supplied
    idempotency key. It must not follow model-provided URLs or execute payloads.
    Agent Effect Gate performs at most one dispatch attempt; a crash can leave its outcome
    unknown. Destination services must implement idempotency for stronger semantics.
    """
    audience: str
    implementation_version: str
    send: Callable[[bytes, str], dict[str, str]]

    def manifest(self, destination_id: str) -> dict[str, str]:
        return {"id": destination_id, "audience": self.audience,
                "implementation_version": self.implementation_version}


class Broker(ToolGate):
    def __init__(self, database: str | Path, key: bytes, *,
                 clock: Callable[[], float] = time.time, sinks: dict[str, Sink] | None = None,
                 audit_anchor: dict[str, Any] | None = None,
                 tools: dict[str, ToolAdapter] | None = None):
        self.clock = clock
        self._sinks = dict(sinks or {})
        for name, sink in self._sinks.items():
            identifier(name)
            text(sink.audience, 500)
            text(sink.implementation_version, 100)
            if not callable(sink.send):
                raise ValueError("Sink.send must be callable")
        self._tools = dict(tools or {})
        for name, tool in self._tools.items():
            identifier(name)
            manifest = loads(canonical(tool.manifest()))
            if manifest.get('effect') not in {'network_read', 'network_write', 'local_code'}:
                raise ValueError('Unsupported tool effect')
            if not callable(tool.prepare) or not callable(tool.invoke):
                raise ValueError('Invalid adapter')
        self.store = Store(database, key, clock, anchor=audit_anchor)
        self._failed = False

    def close(self) -> None:
        self.store.close()

    # --------------------- Trusted control plane ---------------------
    def create_task(self, task_id: str, tenant_id: str, policy: dict[str, Any]) -> dict[str, str]:
        identifier(task_id)
        identifier(tenant_id)
        p = validate_policy(policy)
        value = {"task": task_id, "tenant": tenant_id, "version": 1, "policy": p}
        tokens = {agent: secrets.token_urlsafe(32) for agent in p["agents"]}
        with self.store.transaction() as db:
            db.execute("INSERT INTO tasks(id,tenant,policy,version,policy_mac) VALUES(?,?,?,?,?)",
                       (task_id, tenant_id, canonical(p).decode(), 1, seal(self.store.key, "policy-v1", value)))
            for agent, token in tokens.items():
                db.execute("INSERT INTO sessions(token_hash,task,agent) VALUES(?,?,?)",
                           (digest(token.encode()), task_id, agent))
            self.store.append(db, task_id, "operator", "task_created",
                              {"policy_sha256": digest(canonical(p)), "policy_version": 1})
        return tokens

    def replace_policy(self, task_id: str, policy: dict[str, Any]) -> None:
        """Every change invalidates pending approvals; agent membership stays fixed."""
        p = validate_policy(policy)
        with self.store.transaction() as db:
            task, old = self._policy(db, task_id)
            if p["agents"] != old["agents"]:
                raise Rejected("membership_change_requires_new_task")
            version = task["version"] + 1
            signed = {"task": task_id, "tenant": task["tenant"], "version": version, "policy": p}
            db.execute("UPDATE tasks SET policy=?,version=?,policy_mac=? WHERE id=?",
                       (canonical(p).decode(), version, seal(self.store.key, "policy-v1", signed), task_id))
            self.store.append(db, task_id, "operator", "policy_changed",
                              {"policy_version": version, "policy_sha256": digest(canonical(p))})

    def set_suspended(self, task_id: str, suspended: bool, *, operator: str) -> None:
        identifier(operator)
        if type(suspended) is not bool:
            raise Rejected("invalid_schema")
        with self.store.transaction() as db:
            self._policy(db, task_id)
            db.execute("UPDATE tasks SET suspended=? WHERE id=?", (int(suspended), task_id))
            self.store.append(db, task_id, operator, "task_suspended" if suspended else "task_resumed", {})

    def revoke_session(self, token: str, *, operator: str) -> None:
        identifier(operator)
        with self.store.transaction() as db:
            principal = self._principal(db, token)
            db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (digest(token.encode()),))
            self.store.append(db, principal["task"], operator, "session_revoked",
                              {"agent": principal["agent"]})

    def register_source(self, task_id: str, source_id: str, version: str, document: Any, *,
                        origin: str, origin_kind: str = "operator_import") -> dict[str, str]:
        """Import a captured source on the control plane, not an agent assertion.

        ``origin`` is a protected provenance label, NOT a destination to fetch.
        A host connector must independently verify authenticity and applicability.
        """
        identifier(source_id)
        identifier(version)
        text(origin, 1000)
        if origin_kind not in {"operator_import", "connector_capture", "user_supplied"}:
            raise Rejected("invalid_origin_kind")
        raw = canonical(document)
        if len(raw) > 8_000_000:
            raise Rejected("source_too_large")
        sha = digest(raw)
        metadata = {"origin": origin, "origin_kind": origin_kind, "captured_at": self.clock()}
        signed = {"task": task_id, "id": source_id, "version": version,
                  "sha256": sha, "metadata": metadata}
        with self.store.transaction() as db:
            self._policy(db, task_id)
            db.execute("INSERT INTO sources VALUES(?,?,?,?,?,?,?)",
                       (task_id, source_id, version, raw.decode(), canonical(metadata).decode(),
                        sha, seal(self.store.key, "source-v1", signed)))
            self.store.append(db, task_id, "operator", "source_imported",
                              {"source": source_id, "version": version, "sha256": sha})
        return {"source": source_id, "version": version, "sha256": sha}

    def approval_view(self, proposal_id: str) -> dict[str, Any]:
        """Present through a trusted UI; never infer consent from model text."""
        with self.store.transaction() as db:
            row = self._proposal(db, identifier(proposal_id))
            return {"proposal_id": row["id"], "task_id": row["task"], "agent": row["agent"],
                    "destination": loads(row["destination_manifest"]),
                    "artifact_id": row["artifact"], "payload_sha256": row["payload_sha256"],
                    "policy_version": row["policy_version"], "state": row["state"],
                    "warning": "Approval permits release of exactly these bytes to this audience."}

    def review_payload(self, proposal_id: str) -> bytes:
        """Trusted-reviewer access to the exact proposed bytes. Do not render as active HTML."""
        with self.store.transaction() as db:
            row = self._proposal(db, identifier(proposal_id))
            artifact = self._artifact(db, row["task"], row["agent"], row["artifact"])
            return bytes(artifact["payload"])

    def approve_release(self, proposal_id: str, *, reviewer: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        identifier(reviewer)
        with self.store.transaction() as db:
            row = self._proposal(db, identifier(proposal_id))
            task, p = self._policy(db, row["task"])
            if task["suspended"]:
                raise Rejected("task_suspended")
            self._release_binding(row, task, p, require_adapter=False)
            renewing = row['state'] == 'APPROVED' and self.clock() >= row['expires_at']
            if renewing:
                previous = {"proposal": row['id'], "binding_mac": row['binding_mac'],
                            "reviewer": row['approver'], "expires_at": row['expires_at']}
                if not authenticated(self.store.key, 'approval-v1', previous, row['approval_mac']):
                    raise IntegrityError('Approval authentication failed')
            if row['state'] != 'PENDING' and not renewing:
                raise Rejected('proposal_not_pending')
            ttl = p["approval_ttl_seconds"] if ttl_seconds is None else ttl_seconds
            if type(ttl) is not int or not 1 <= ttl <= p["approval_ttl_seconds"]:
                raise Rejected("invalid_approval_ttl")
            expires_at = self.clock() + ttl
            signed = {"proposal": row["id"], "binding_mac": row["binding_mac"],
                      "reviewer": reviewer, "expires_at": expires_at}
            db.execute("UPDATE proposals SET state='APPROVED',approver=?,expires_at=?,approval_mac=? WHERE id=?",
                       (reviewer, expires_at, seal(self.store.key, "approval-v1", signed), row["id"]))
            self.store.append(db, row["task"], reviewer, "release_approval_renewed" if renewing else "release_approved",
                              {"proposal_id": row["id"], "expires_at": expires_at})
            return {"proposal_id": row["id"], "state": "APPROVED", "expires_at": expires_at}

    def revoke_release(self, proposal_id: str, *, reviewer: str) -> None:
        identifier(reviewer)
        with self.store.transaction() as db:
            row = self._proposal(db, identifier(proposal_id))
            if row["state"] not in {"PENDING", "APPROVED"}:
                raise Rejected("dispatch_already_started")
            db.execute("UPDATE proposals SET state='REVOKED' WHERE id=?", (proposal_id,))
            self.store.append(db, row["task"], reviewer, "release_revoked", {"proposal_id": proposal_id})

    def reconcile_effect(self, kind: str, record_id: str, *, outcome: str,
                         operator: str, evidence_reference: str) -> dict[str, Any]:
        """Trusted, QUIESCED operator recovery of an uncertain effect.

        The CLI takes an exclusive state lease and requires task suspension.
        Direct Python hosts must stop all dispatchers before calling this method.
        Retain the independent evidence externally; the journal binds its reference
        without copying potentially sensitive evidence into the public notices.
        """
        identifier(operator)
        identifier(record_id)
        text(evidence_reference, 500)
        if not evidence_reference.strip() or kind not in {'tool', 'release'} or outcome not in {'succeeded', 'failed'}:
            raise Rejected('invalid_reconciliation')
        with self.store.transaction() as db:
            row = self._tool_call(db, record_id) if kind == 'tool' else self._proposal(db, record_id)
            task, _ = self._policy(db, row['task'])
            if not task['suspended']:
                raise Rejected('reconciliation_requires_suspension')
            if row['state'] not in {'UNKNOWN', 'DISPATCHING'}:
                raise Rejected('effect_not_uncertain')
            state = 'FAILED' if outcome == 'failed' else ('SUCCEEDED' if kind == 'tool' else 'DELIVERED')
            table = 'tool_calls' if kind == 'tool' else 'proposals'
            db.execute('UPDATE ' + table + ' SET state=? WHERE id=?', (state, record_id))
            reference_sha = digest(evidence_reference.encode('utf-8'))
            self.store.append(db, row['task'], operator, 'effect_reconciled',
                              {'kind': kind, 'id': record_id, 'previous_state': row['state'],
                               'state': state, 'evidence_reference_sha256': reference_sha})
            return {'id': record_id, 'kind': kind, 'state': state, 'retry_dispatch': False,
                    'evidence_reference_sha256': reference_sha}

    # ------------------------ Agent data plane ------------------------
    def host_view(self, session_token: str, operation: str) -> dict[str, Any]:
        """Trusted harness ONLY: fresh, non-persistent context/final rendering.

        This capability is not an operation on JSONL, MCP, or the reviewer API.
        It cannot take arbitrary arguments, dispatch tools, or bypass suspension.
        """
        if operation not in {'context', 'answer'}:
            raise ValueError('Host view only supports context and answer')
        if self._failed:
            return {'ok': False, 'error': 'broker_stopped'}
        try:
            with self.store.transaction() as db:
                principal = self._principal(db, session_token)
                task, policy = self._policy(db, principal['task'])
                view = (self._context(db, task, policy, principal['agent']) if operation == 'context'
                        else self._answer(db, task, policy, principal['agent'], record_evidence=False))
                return {'ok': True, 'result': view}
        except Rejected:
            return {'ok': False, 'error': 'unauthorized'}
        except StoreBusy:
            return {'ok': False, 'error': 'broker_busy', 'retryable': True,
                    'retry_condition': 'storage_available'}
        except (sqlite3.Error, IntegrityError, OSError):
            self._failed = True
            return {'ok': False, 'error': 'integrity_or_storage_failure', 'action_execution_stopped': True}

    def handle(self, session_token: str, request: dict[str, Any] | str | bytes) -> dict[str, Any]:
        """Bounded agent data plane: actions and reads have independent quotas.

        Each read (including repeated IDs) spends read quota and stores only a
        request hash. Successful immutable writes are idempotent. Retries of live
        or denied writes spend their independent retry quota, not another action reservation. Once a
        quota is exhausted, its refusals make NO durable changes and are not
        security denials. Successful reads and unchanged polls do not add audit
        events. Effects, policy refusals and state transitions remain journaled.
        """
        if self._failed:
            return {'ok': False, 'error': 'broker_stopped'}
        job = None
        try:
            with self.store.transaction() as db:
                try:
                    principal = self._principal(db, session_token)
                except Rejected:
                    return {'ok': False, 'error': 'unauthorized'}
                task_id, agent = principal['task'], principal['agent']
                task, p = self._policy(db, task_id)
                request_id = fingerprint = operation = old = read_old = None
                cached = None
                parse_error = None
                status_poll = False
                try:
                    if isinstance(request, (str, bytes)):
                        action = loads(request)
                    else:
                        encoded = canonical(request)
                        if len(encoded) > MAX_WIRE_BYTES:
                            raise Rejected('request_too_large')
                        action = loads(encoded)
                    exact_keys(action, {'request_id', 'operation', 'arguments'})
                    request_id = identifier(action['request_id'])
                    fingerprint = digest(canonical(action))
                    operation = action['operation']
                    if not isinstance(operation, str) or operation not in OPERATIONS:
                        operation = None
                        raise Rejected('unknown_operation')
                    old = db.execute('SELECT * FROM requests WHERE task=? AND agent=? AND id=?',
                                     (task_id, agent, request_id)).fetchone()
                    read_old = db.execute('SELECT * FROM read_request_hashes WHERE task=? AND agent=? AND id=?',
                                          (task_id, agent, request_id)).fetchone()
                    existing = old or read_old
                    if existing and existing['request_sha256'] != fingerprint:
                        raise Rejected('request_id_conflict')
                    args = exact_keys(action['arguments'], SCHEMAS[operation])
                    if operation == 'execute_tool':
                        poll_row = self._tool_call(db, args['call_id'], task_id, agent)
                        status_poll = poll_row['state'] in TERMINAL | {'DISPATCHING'}
                    elif operation == 'execute_release':
                        poll_row = self._proposal(db, identifier(args['proposal_id']), task_id=task_id, agent=agent)
                        status_poll = poll_row['state'] in {'DISPATCHING', 'DELIVERED', 'FAILED', 'UNKNOWN', 'REVOKED'}
                    if old:
                        cached = self._cache_response(operation, loads(old['response'], limit=8_000_000))
                        if operation == 'submit_answer' and cached.get('ok'):
                            # This returns a fresh answer below, subject to read quota.
                            pass
                        elif operation not in READ_OPERATIONS | LIVE_OPERATIONS and cached.get('ok'):
                            # Remove private bindings from pre-0.3 cached tool proposals too.
                            if operation == 'propose_tool' and 'manifest' in cached.get('result', {}):
                                cached['result']['manifest'] = public_manifest(cached['result']['manifest'])
                            return cached
                except Rejected as exc:
                    parse_error = str(exc)
                is_read = (operation in READ_OPERATIONS or status_poll or
                           (operation == 'submit_answer' and cached is not None and cached.get('ok', False)))
                if is_read:
                    column, limit, exhausted = 'read_requests', p.get('max_read_requests', 2000), 'read_budget_exhausted'
                elif old is not None or read_old is not None:
                    column, limit, exhausted = 'retry_requests', p.get('max_retry_requests', 1000), 'retry_budget_exhausted'
                else:
                    column, limit, exhausted = 'requests', p['max_requests'], 'request_budget_exhausted'
                if task[column] >= limit:
                    return {'ok': False, 'error': exhausted, 'retryable': False}
                # Only one cell changes per admitted attempt; over-limit calls do
                # not change counters, incidents, caches, or the append-only audit.
                db.execute('UPDATE tasks SET ' + column + '=' + column + '+1 WHERE id=?', (task_id,))
                task, p = self._policy(db, task_id)
                try:
                    if parse_error:
                        raise Rejected(parse_error)
                    if task['suspended'] and operation not in {'answer', 'context', 'inbox'}:
                        raise Rejected('task_suspended')
                    db.execute('SAVEPOINT operation')
                    try:
                        if operation == 'submit_answer' and cached and cached.get('ok'):
                            result, job = self._answer(db, task, p, agent), None
                        else:
                            result, job = self._dispatch(db, task, p, agent, operation, args)
                    except Rejected:
                        db.execute('ROLLBACK TO operation')
                        db.execute('RELEASE operation')
                        raise
                    db.execute('RELEASE operation')
                    response = {'ok': True, 'result': result}
                    if not is_read and self._cache_response(operation, response) != cached:
                        self.store.append(db, task_id, agent, 'action_allowed',
                                          {'operation': operation, 'request_sha256': fingerprint})
                except Rejected as exc:
                    code = str(exc)
                    response = {'ok': False, 'error': code}
                    if code in {'approval_required', 'approval_expired'}:
                        response.update(retryable=True, retry_condition='approval_state_changed')
                        if response != cached:
                            self.store.append(db, task_id, agent, 'action_waiting',
                                              {'operation': operation, 'request_sha256': fingerprint})
                    elif code in {'request_budget_exhausted', 'read_budget_exhausted', 'retry_budget_exhausted',
                                  'tool_plan_quota_exceeded', 'tool_budget_exhausted',
                                  'artifact_quota_exceeded', 'message_quota_exceeded', 'observation_quota_exceeded'}:
                        # Capacity exhaustion is not evidence of a policy attack.
                        response['retryable'] = False
                    elif code in {'citation_quote_mismatch', 'request_id_conflict'}:
                        # The input remains rejected. Correction is bounded by
                        # ordinary action/retry quotas, not the attack breaker.
                        response.update(retryable=False, correction_required=True)
                        if response != cached:
                            self.store.append(db, task_id, agent, 'action_correction_needed',
                                              {'code': code, 'request_sha256': fingerprint})
                    elif response != cached:
                        self._deny(db, task_id, agent, code, fingerprint, p)
                if request_id and fingerprint and parse_error != 'request_id_conflict':
                    if is_read:
                        db.execute('INSERT OR IGNORE INTO read_request_hashes VALUES(?,?,?,?)',
                                   (task_id, agent, request_id, fingerprint))
                    elif self._cache_response(operation, response) != cached:
                        db.execute('INSERT INTO requests VALUES(?,?,?,?,?) ON CONFLICT(task,agent,id) '
                                   'DO UPDATE SET response=excluded.response',
                                   (task_id, agent, request_id, fingerprint,
                                    canonical(self._cache_response(operation, response)).decode()))
            if job is not None:
                if job.get('kind') == 'tool':
                    return self._deliver_tool(job, task_id, agent, request_id, fingerprint)
                return self._deliver(job, task_id, agent, request_id, fingerprint)
            return response
        except StoreBusy:
            return {'ok': False, 'error': 'broker_busy', 'retryable': True,
                    'retry_condition': 'storage_available'}
        except (sqlite3.Error, IntegrityError, OSError):
            self._failed = True
            return {'ok': False, 'error': 'integrity_or_storage_failure', 'action_execution_stopped': True}

    @staticmethod
    def _cache_response(operation, response):
        if operation == 'execute_tool' and response.get('ok') and isinstance(response.get('result'), dict):
            return {**response, 'result': {k: v for k, v in response['result'].items() if k != 'observation'}}
        return response

    def _dispatch(self, db: sqlite3.Connection, task: sqlite3.Row, p: dict[str, Any], agent: str,
                  operation: str, a: dict[str, Any]) -> tuple[dict[str, Any], Any]:
        task_id = task["id"]
        if operation in TOOL_SCHEMAS:
            return self._dispatch_tool(db, task, p, agent, operation, a)
        if operation == "context":
            return self._context(db, task, p, agent), None
        if operation == "answer":
            return self._answer(db, task, p, agent, record_evidence=True), None
        if operation == "resolve_field":
            field_id = identifier(a["field_id"])
            field = next((f for f in p["fields"] if f["id"] == field_id), None)
            if field is None:
                raise Rejected("field_not_in_contract")
            return self._resolve(db, task, field), None
        if operation == "put_artifact":
            if not isinstance(a["media_type"], str) or a["media_type"] not in MEDIA_TYPES:
                raise Rejected("invalid_media_type")
            raw = text(a["data_b64"], (p["max_artifact_bytes"] + 2) * 4 // 3 + 4)
            try:
                payload = base64.b64decode(raw, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise Rejected("invalid_base64") from exc
            used = db.execute("SELECT coalesce(sum(length(payload)),0) FROM artifacts WHERE task=?", (task_id,)).fetchone()[0]
            if len(payload) > p["max_artifact_bytes"] or used + len(payload) > p["max_total_artifact_bytes"]:
                raise Rejected("artifact_quota_exceeded")
            artifact_id, sha = "art_" + secrets.token_hex(16), digest(payload)
            signed = {"id": artifact_id, "task": task_id, "owner": agent,
                      "media_type": a["media_type"], "sha256": sha}
            db.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?)",
                       (artifact_id, task_id, agent, a["media_type"], payload, sha,
                        seal(self.store.key, "artifact-v1", signed)))
            return {"artifact_id": artifact_id, "sha256": sha, "bytes": len(payload),
                    "classification": "task_private", "evidence_status": "unverified_model_content"}, None
        if operation == "read_artifact":
            artifact = self._artifact(db, task_id, agent, identifier(a["artifact_id"]))
            return {"artifact_id": artifact["id"], "sha256": artifact["sha256"],
                    "media_type": artifact["media_type"], "data_b64": base64.b64encode(artifact["payload"]).decode(),
                    "evidence_status": "unverified_model_content"}, None
        if operation == "share_artifact":
            recipient = identifier(a["recipient"])
            self._channel(p, agent, recipient)
            artifact = self._artifact(db, task_id, agent, identifier(a["artifact_id"]))
            if artifact["owner"] != agent:
                raise Rejected("artifact_not_owned")
            db.execute("INSERT OR IGNORE INTO artifact_access VALUES(?,?)", (artifact["id"], recipient))
            return {"artifact_id": artifact["id"], "recipient": recipient, "scope": "same_task_only"}, None
        if operation == "send_message":
            recipient = identifier(a["recipient"])
            self._channel(p, agent, recipient)
            message = text(a["text"], p["max_message_bytes"])
            count = db.execute("SELECT count(*) FROM messages WHERE task=?", (task_id,)).fetchone()[0]
            if count >= p["max_messages"]:
                raise Rejected("message_quota_exceeded")
            message_id = "msg_" + secrets.token_hex(16)
            db.execute("INSERT INTO messages VALUES(?,?,?,?,?,?)",
                       (message_id, task_id, agent, recipient, message, self.clock()))
            return {"message_id": message_id, "scope": "same_task_only"}, None
        if operation == "inbox":
            return {"trust": "untrusted_data", "messages": self._inbox(db, task_id, agent)}, None
        if operation == "propose_release":
            if p["local_only"]:
                raise Rejected("local_only")
            destination = identifier(a["destination_id"])
            if destination not in p["destinations"]:
                raise Rejected("destination_not_allowed")
            if destination not in self._sinks:
                raise Rejected("destination_unavailable")
            artifact = self._artifact(db, task_id, agent, identifier(a["artifact_id"]))
            if artifact["owner"] != agent:
                raise Rejected("artifact_not_owned")
            proposal_id, now = "rel_" + secrets.token_hex(16), self.clock()
            manifest = self._sinks[destination].manifest(destination)
            binding = {"id": proposal_id, "task": task_id, "agent": agent, "artifact": artifact["id"],
                       "destination": destination, "destination_manifest": manifest,
                       "policy_version": task["version"], "payload_sha256": artifact["sha256"],
                       "created_at": now}
            db.execute("INSERT INTO proposals(id,task,agent,artifact,destination,policy_version,payload_sha256,"
                       "binding_mac,destination_manifest,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,'PENDING',?)",
                       (proposal_id, task_id, agent, artifact["id"], destination, task["version"], artifact["sha256"],
                        seal(self.store.key, "proposal-v1", binding), canonical(manifest).decode(), now))
            return {"proposal_id": proposal_id, "state": "PENDING", "approval_required": True,
                    "payload_sha256": artifact["sha256"], "destination": manifest}, None
        if operation == "execute_release":
            row = self._proposal(db, identifier(a["proposal_id"]), task_id=task_id, agent=agent)
            if row["state"] in {"DISPATCHING", "DELIVERED", "FAILED", "UNKNOWN", "REVOKED"}:
                return self._release_status(row), None
            self._release_binding(row, task, p)
            if row["state"] != "APPROVED":
                raise Rejected("approval_required")
            grant = {"proposal": row["id"], "binding_mac": row["binding_mac"],
                     "reviewer": row["approver"], "expires_at": row["expires_at"]}
            if not authenticated(self.store.key, "approval-v1", grant, row["approval_mac"]):
                raise IntegrityError("Approval authentication failed")
            if self.clock() >= row["expires_at"]:
                raise Rejected("approval_expired")
            artifact = self._artifact(db, task_id, agent, row["artifact"])
            if artifact["sha256"] != row["payload_sha256"]:
                raise IntegrityError("Release bytes do not match approval")
            db.execute("UPDATE proposals SET state='DISPATCHING' WHERE id=?", (row["id"],))
            self.store.append(db, task_id, agent, "release_dispatch_intent",
                              {"proposal_id": row["id"], "payload_sha256": row["payload_sha256"],
                               "destination": row["destination"]})
            job = {"id": row["id"], "payload": bytes(artifact["payload"]), "sink": self._sinks[row["destination"]]}
            return {"proposal_id": row["id"], "state": "DISPATCHING",
                    "outcome": "unknown_until_confirmed"}, job
        raise Rejected("unknown_operation")

    def _deliver(self, job: dict[str, Any], task_id: str, agent: str, request_id: str,
                 fingerprint: str) -> dict[str, Any]:
        # The durable DISPATCHING transition is committed BEFORE invoking a sink.
        # No automatic retry, including after restart, an exception or a timeout.
        receipt, state = None, "UNKNOWN"
        try:
            receipt = job["sink"].send(job["payload"], job["id"])
            exact_keys(receipt, {"receipt_id"})
            text(receipt["receipt_id"], 200)
            state = "DELIVERED"
        except Exception:
            # Never disclose adapter exception strings: they may contain secrets.
            receipt = None
        try:
            with self.store.transaction() as db:
                db.execute("UPDATE proposals SET state=?,receipt=? WHERE id=? AND state='DISPATCHING'",
                           (state, canonical(receipt).decode() if receipt else None, job["id"]))
                event = self.store.append(db, task_id, agent, "release_result",
                                          {"proposal_id": job["id"], "state": state})
                if state == "UNKNOWN":
                    self._incident(db, task_id, "release_outcome_unknown", event, severity="high")
                result = {"proposal_id": job["id"], "state": state, "receipt": receipt}
                response = {"ok": True, "result": result}
                db.execute("UPDATE requests SET response=? WHERE task=? AND agent=? AND id=? AND request_sha256=?",
                           (canonical(response).decode(), task_id, agent, request_id, fingerprint))
            return response
        except StoreBusy:
            return {'ok': False, 'error': 'post_dispatch_audit_unavailable', 'delivery_outcome': 'unknown',
                    'proposal_id': job['id'], 'retryable': False, 'retry_dispatch': False}
        except (sqlite3.Error, IntegrityError, OSError):
            self._failed = True
            return {"ok": False, "error": "post_dispatch_audit_unavailable", "delivery_outcome": "unknown",
                    "proposal_id": job["id"], "action_execution_stopped": True}

    # ---------------------- Protected state views ---------------------
    def _principal(self, db: sqlite3.Connection, token: str) -> sqlite3.Row:
        if not isinstance(token, str) or not 20 <= len(token) <= 200 or not token.isascii():
            raise Rejected("unauthorized")
        row = db.execute("SELECT * FROM sessions WHERE token_hash=? AND revoked=0", (digest(token.encode()),)).fetchone()
        if row is None:
            raise Rejected("unauthorized")
        return row

    def _policy(self, db: sqlite3.Connection, task_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            raise Rejected("task_not_found")
        p = loads(row["policy"])
        signed = {"task": row["id"], "tenant": row["tenant"], "version": row["version"], "policy": p}
        if not authenticated(self.store.key, "policy-v1", signed, row["policy_mac"]):
            raise IntegrityError("Policy authentication failed")
        return row, p

    def _artifact(self, db: sqlite3.Connection, task_id: str, agent: str, artifact_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM artifacts WHERE id=? AND task=?", (artifact_id, task_id)).fetchone()
        if row is None:
            raise Rejected("artifact_not_found")
        if row["owner"] != agent:
            _, p = self._policy(db, task_id)
            if [row["owner"], agent] not in p["channels"] or db.execute(
                    "SELECT 1 FROM artifact_access WHERE artifact=? AND agent=?",
                    (artifact_id, agent)).fetchone() is None:
                raise Rejected("artifact_not_found")
        signed = {"id": row["id"], "task": row["task"], "owner": row["owner"],
                  "media_type": row["media_type"], "sha256": row["sha256"]}
        if digest(bytes(row["payload"])) != row["sha256"] or not authenticated(
                self.store.key, "artifact-v1", signed, row["mac"]):
            raise IntegrityError("Artifact authentication failed")
        return row

    def _proposal(self, db: sqlite3.Connection, proposal_id: str, *, task_id: str | None = None,
                  agent: str | None = None) -> sqlite3.Row:
        row = db.execute("SELECT * FROM proposals WHERE id=?", (proposal_id,)).fetchone()
        if row is None or (task_id is not None and row["task"] != task_id) or (agent is not None and row["agent"] != agent):
            raise Rejected("proposal_not_found")
        binding = {k: row[k] for k in ("id", "task", "agent", "artifact", "destination", "policy_version", "payload_sha256", "created_at")}
        binding["destination_manifest"] = loads(row["destination_manifest"])
        if not authenticated(self.store.key, "proposal-v1", binding, row["binding_mac"]):
            raise IntegrityError("Proposal authentication failed")
        return row

    def _release_binding(self, row: sqlite3.Row, task: sqlite3.Row, p: dict[str, Any], *, require_adapter: bool = True) -> None:
        if p["local_only"]:
            raise Rejected("local_only")
        if row["destination"] not in p["destinations"]:
            raise Rejected("destination_not_allowed")
        sink = self._sinks.get(row["destination"])
        if sink is None and require_adapter:
            raise Rejected("destination_unavailable")
        if row["policy_version"] != task["version"] or (sink is not None and sink.manifest(row["destination"]) != loads(row["destination_manifest"])):
            raise Rejected("approval_binding_changed")

    @staticmethod
    def _channel(p: dict[str, Any], agent: str, recipient: str) -> None:
        if [agent, recipient] not in p["channels"]:
            raise Rejected("channel_not_allowed")

    def _resolve(self, db: sqlite3.Connection, task: sqlite3.Row, field: dict[str, Any]) -> dict[str, Any]:
        row = db.execute("SELECT * FROM sources WHERE task=? AND id=? AND version=?",
                         (task["id"], field["source"], field["version"])).fetchone()
        if row is None:
            raise Rejected("source_missing")
        metadata = loads(row["metadata"])
        signed = {"task": row["task"], "id": row["id"], "version": row["version"],
                  "sha256": row["sha256"], "metadata": metadata}
        if digest(row["document"].encode()) != row["sha256"] or not authenticated(
                self.store.key, "source-v1", signed, row["mac"]):
            raise IntegrityError("Source authentication failed")
        if field.get("expected_sha256") is not None and field["expected_sha256"] != row["sha256"]:
            raise Rejected("source_digest_mismatch")
        value = evaluate(loads(row["document"], limit=8_000_000), field)
        provenance = {"source_id": row["id"], "source_version": row["version"], "sha256": row["sha256"],
                      "sha256_representation": "canonical-json-v1",
                      "origin": metadata["origin"], "origin_kind": metadata["origin_kind"],
                      "captured_at": metadata["captured_at"], "pointer": field["pointer"],
                      "operation": field["operation"]}
        if field["operation"] == "filter_table":
            provenance.update(where=field["where"], columns=field["columns"])
        evidence = {"task": task["id"], "policy_version": task["version"], "field": field["id"],
                    "value": value, "provenance": provenance}
        evidence_id = "ev_" + seal(self.store.key, "evidence-v1", evidence)
        return {"field_id": field["id"], "label": field["label"], "status": "supported",
                "value": value, "evidence_id": evidence_id, "provenance": provenance}

    def _artifact_catalog(self, db: sqlite3.Connection, task_id: str, agent: str) -> list[dict[str, Any]]:
        out = []
        rows = db.execute("SELECT DISTINCT a.id FROM artifacts a LEFT JOIN artifact_access x ON x.artifact=a.id "
                          "WHERE a.task=? AND (a.owner=? OR x.agent=?) ORDER BY a.id", (task_id, agent, agent)).fetchall()
        for candidate in rows:
            try:
                row = self._artifact(db, task_id, agent, candidate["id"])
            except Rejected:
                continue  # A formerly shared artifact may have had its channel revoked.
            out.append({"artifact_id": row["id"], "owner": row["owner"], "sha256": row["sha256"],
                        "media_type": row["media_type"], "bytes": len(row["payload"]),
                        "classification": "task_private", "evidence_status": "unverified_model_content"})
        return out

    def _inbox(self, db: sqlite3.Connection, task_id: str, agent: str) -> list[dict[str, Any]]:
        return [dict(row) for row in db.execute("SELECT id,sender,content,timestamp FROM messages "
                                                "WHERE task=? AND recipient=? ORDER BY timestamp,id", (task_id, agent))]

    def _notices(self, db: sqlite3.Connection, task_id: str) -> list[dict[str, Any]]:
        out = []
        for row in db.execute("SELECT id,code,occurrences,status FROM incidents WHERE task=? ORDER BY first_seen,id", (task_id,)):
            out.append({"incident_id": row["id"], "code": row["code"], "occurrences": row["occurrences"],
                        "review_status": row["status"], "summary": NOTICES.get(row["code"], "An invalid or unavailable action was recorded.")})
        return out

    @staticmethod
    def _release_status(row: sqlite3.Row) -> dict[str, Any]:
        return {"proposal_id": row["id"], "state": row["state"],
                "outcome": "unknown_or_in_progress" if row["state"] == "DISPATCHING" else row["state"].lower(),
                "receipt": loads(row["receipt"]) if row["receipt"] else None}

    def _releases(self, db: sqlite3.Connection, task_id: str) -> list[dict[str, Any]]:
        return [self._release_status(r) for r in db.execute("SELECT * FROM proposals WHERE task=? ORDER BY created_at,id", (task_id,))]

    def _context(self, db: sqlite3.Connection, task: sqlite3.Row, p: dict[str, Any], agent: str) -> dict[str, Any]:
        # No agent summary is accepted. Roles are not reconstructed from transcript text.
        context = {
            "format": "agent-effect-gate-context-v1", "task_id": task["id"], "agent": agent,
            "scope_id": seal(self.store.key, "runtime-scope-v1", {"task_id": task["id"], "agent": agent}),
            "control": {"policy_version": task["version"], "policy_sha256": digest(canonical(p)),
                        "local_only": p["local_only"], "suspended": bool(task["suspended"]),
                        "required_fields": p["fields"], "channels": p["channels"],
                        "destinations": p["destinations"],
                        "budgets": self._budgets(task, p)},
            "tools": self._tools_for(p), "tool_calls": self._recent_tools(db, task["id"], agent),
            "answer_mode": p.get("answer_mode", "evidence"),
            "notices": self._notices(db, task["id"]), "releases": self._releases(db, task["id"]),
            "untrusted_data": {"messages": self._inbox(db, task["id"], agent),
                               "artifacts": self._artifact_catalog(db, task["id"], agent)},
            "resume_rule": "Refresh context from the broker; model-authored summaries never become authority.",
        }
        return {"snapshot": context, "mac": seal(self.store.key, "context-v1", context)}

    @staticmethod
    def _budgets(task, policy):
        return {'actions': {'used': task['requests'], 'limit': policy['max_requests'],
                            'remaining': max(0, policy['max_requests'] - task['requests'])},
                'reads': {'used': task['read_requests'], 'limit': policy.get('max_read_requests', 2000),
                          'remaining': max(0, policy.get('max_read_requests', 2000) - task['read_requests'])},
                'retries': {'used': task['retry_requests'], 'limit': policy.get('max_retry_requests', 1000),
                            'remaining': max(0, policy.get('max_retry_requests', 1000) - task['retry_requests'])}}

    def _answer(self, db: sqlite3.Connection, task: sqlite3.Row, p: dict[str, Any], agent: str,
                *, record_evidence: bool = False) -> dict[str, Any]:
        if p.get('answer_mode', 'evidence') == 'model':
            return self._model_answer(db, task, p, agent)
        fields = []
        for field in p["fields"]:
            try:
                fields.append(self._resolve(db, task, field))
            except Rejected as exc:
                code = str(exc)
                if record_evidence and not db.execute('SELECT 1 FROM incidents WHERE task=? AND code=?',
                                                       (task['id'], code)).fetchone():
                    event = self.store.append(db, task['id'], agent, 'evidence_unavailable',
                                              {'field_id': field['id'], 'code': code})
                    self._incident(db, task['id'], code, event, severity='medium')
                fields.append({"field_id": field["id"], "label": field["label"], "status": "unavailable",
                               "value": None, "reason": code})
        answer = {
            "format": "agent-effect-gate-answer-v1", "task_id": task["id"], "policy_version": task["version"],
            "evidence_complete": all(f["status"] == "supported" for f in fields),
            "fields": fields, "notices": self._notices(db, task["id"]),
            "releases": self._releases(db, task["id"]), "suspended": bool(task["suspended"]),
            "artifacts": self._artifact_catalog(db, task["id"], agent),
            "assurance": "Values are derived from the bound captured sources; source truth is not independently guaranteed.",
        }
        return {"answer": answer, "mac": seal(self.store.key, "answer-v1", answer)}

    def _deny(self, db: sqlite3.Connection, task_id: str, agent: str, code: str,
              fingerprint: str | None, p: dict[str, Any]) -> None:
        event = self.store.append(db, task_id, agent, "action_denied",
                                  {"code": code, "request_sha256": fingerprint})
        self._incident(db, task_id, code, event,
                       severity="high" if code in {"local_only", "channel_not_allowed", "approval_binding_changed"} else "medium")
        db.execute("UPDATE tasks SET denials=denials+1 WHERE id=?", (task_id,))
        n = db.execute("SELECT denials,suspended FROM tasks WHERE id=?", (task_id,)).fetchone()
        if n["denials"] >= p["max_denials"] and not n["suspended"]:
            db.execute("UPDATE tasks SET suspended=1 WHERE id=?", (task_id,))
            self.store.append(db, task_id, "broker", "circuit_breaker_opened", {"denial_count": n["denials"]})

    def _incident(self, db: sqlite3.Connection, task_id: str, code: str, event: int, *, severity: str) -> str:
        now = self.clock()
        row = db.execute("SELECT * FROM incidents WHERE task=? AND code=?", (task_id, code)).fetchone()
        if row:
            # New occurrences invalidate a previously completed publication decision.
            status = "FLAGGED" if row["status"] in {"PUBLISHED", "NOT_DISCLOSING", "APPROVED_FOR_PUBLICATION"} else row["status"]
            db.execute("UPDATE incidents SET last_seen=?,last_event=?,occurrences=occurrences+1,status=? WHERE id=?",
                       (now, event, status, row["id"]))
            return row["id"]
        incident_id = "inc_" + secrets.token_hex(16)
        db.execute("INSERT INTO incidents(id,task,code,severity,first_seen,last_seen,occurrences,first_event,last_event,status) "
                   "VALUES(?,?,?,?,?,?,1,?,?,'FLAGGED')", (incident_id, task_id, code, severity, now, now, event, event))
        return incident_id

    # ------------------------ Incident control plane ------------------------
    def flag_incident(self, task_id: str, *, operator: str) -> str:
        identifier(operator)
        with self.store.transaction() as db:
            self._policy(db, task_id)
            event = self.store.append(db, task_id, operator, "operator_flag", {})
            return self._incident(db, task_id, "operator_flag", event, severity="unassessed")

    def record_runtime_notice(self, task_id: str, code: str) -> str:
        """Trusted harness only. Deliberately no arbitrary runtime error text."""
        if code not in {"runtime_step_budget_exhausted", "model_adapter_failed"}:
            raise Rejected("invalid_runtime_notice")
        with self.store.transaction() as db:
            self._policy(db, task_id)
            existing = db.execute('SELECT id FROM incidents WHERE task=? AND code=?', (task_id, code)).fetchone()
            if existing:
                return existing['id']
            event = self.store.append(db, task_id, "runtime", "runtime_notice", {"code": code})
            return self._incident(db, task_id, code, event, severity="medium")

    def list_incidents(self, task_id: str | None = None) -> list[dict[str, Any]]:
        with self.store.transaction() as db:
            rows = db.execute("SELECT * FROM incidents" + (" WHERE task=?" if task_id else "") + " ORDER BY first_seen,id",
                              (task_id,) if task_id else ())
            return [dict(r) for r in rows]

    def triage_incident(self, incident_id: str, *, owner: str, track: str, due_at: float,
                        severity: str, third_party: str = "unknown") -> None:
        identifier(owner)
        if track not in {"ready", "minor", "larger"} or severity not in {"low", "medium", "high", "critical", "unassessed"}:
            raise Rejected("invalid_triage")
        if type(due_at) not in (float, int) or not math.isfinite(due_at) or due_at <= self.clock():
            raise Rejected("invalid_deadline")
        if third_party not in {"yes", "no", "unknown"}:
            raise Rejected("invalid_third_party_status")
        if third_party != "no" and track != "larger":
            raise Rejected("third_party_review_required")
        with self.store.transaction() as db:
            row = self._get_incident(db, incident_id)
            db.execute("UPDATE incidents SET owner=?,track=?,due_at=?,severity=?,third_party=?,status='INVESTIGATING' WHERE id=?",
                       (owner, track, due_at, severity, third_party, incident_id))
            self.store.append(db, row["task"], owner, "incident_triaged",
                              {"incident_id": incident_id, "track": track, "due_at": due_at, "severity": severity})

    def due_incidents(self) -> list[dict[str, Any]]:
        """Read for an operator scheduler. This function does not send notifications."""
        return [r for r in self.list_incidents() if r["status"] not in {"PUBLISHED", "NOT_DISCLOSING"}
                and (r["due_at"] is None or r["due_at"] <= self.clock())]

    def disclosure_draft(self, incident_id: str) -> dict[str, Any]:
        """Redacted, bounded draft; intentionally contains explicit unknowns."""
        with self.store.transaction() as db:
            row = self._get_incident(db, incident_id)
            _, p = self._policy(db, row["task"])
            return {"report_id": row["id"], "observed_behavior": NOTICES.get(row["code"], "An invalid or unavailable action was recorded."),
                    "mechanism_code": row["code"], "severity": row["severity"], "external_impact": "unassessed",
                    "setting": p["stage"], "model_family": p["model_family"], "observed_from": row["first_seen"],
                    "observed_to": row["last_seen"], "discovered_at": row["first_seen"],
                    "occurrences": row["occurrences"], "detection": "Broker event or explicit operator flag",
                    "investigation_scope": "Events visible to this broker only",
                    "interpretation": "Requires human investigation; a denial is not proof of model intent",
                    "unanswered_questions": ["Causal mechanism", "Any behavior outside broker visibility", "External impact"],
                    "mitigations": ["Broker policy enforcement", "Human investigation pending"],
                    "track": row["track"], "review_status": row["status"], "publication_authorized": False}

    def record_disclosure_decision(self, incident_id: str, *, reviewer: str, decision: str,
                                   security_reviewed: bool, third_party_notified: bool,
                                   rationale: str, report: dict[str, Any] | None = None) -> None:
        """Record approval of a reviewed local report; does NOT publish to the Internet.

        Independent reviewer/owner separation is a procedural check. The hosting
        application must authenticate real people rather than trust user-supplied IDs.
        """
        identifier(reviewer)
        text(rationale, 4000)
        if not rationale.strip() or decision not in {"publish", "do_not_disclose", "escalate"}:
            raise Rejected("invalid_disclosure_decision")
        if type(security_reviewed) is not bool or type(third_party_notified) is not bool:
            raise Rejected("invalid_review")
        with self.store.transaction() as db:
            row = self._get_incident(db, incident_id)
            if row["owner"] is None or reviewer == row["owner"]:
                raise Rejected("independent_review_required")
            if decision == "publish":
                if not security_reviewed:
                    raise Rejected("security_review_required")
                if row["third_party"] == "unknown" or (row["third_party"] == "yes" and not third_party_notified):
                    raise Rejected("third_party_review_required")
                required = {"observed_behavior", "severity", "external_impact", "setting", "model_family", "observed_from",
                            "observed_to", "discovered_at", "detection", "investigation_scope", "interpretation",
                            "unanswered_questions", "mitigations"}
                exact_keys(report, required, {"report_id", "mechanism_code", "occurrences", "track", "review_status", "publication_authorized"})
                if len(canonical(report)) > 32000:
                    raise Rejected("report_too_large")
                if report["severity"] not in {"low", "medium", "high", "critical", "unassessed"} or report["setting"] not in {"training", "evaluation", "testing", "deployment"}:
                    raise Rejected("incomplete_report")
                text(report["model_family"], 100)
                if not report["model_family"].strip():
                    raise Rejected("incomplete_report")
                for key in ("observed_from", "observed_to", "discovered_at"):
                    if type(report[key]) not in (int, float) or not math.isfinite(report[key]):
                        raise Rejected("incomplete_report")
                if report["observed_from"] > report["observed_to"]:
                    raise Rejected("incomplete_report")
                for key in ("unanswered_questions", "mitigations"):
                    if not isinstance(report[key], list) or len(report[key]) > 100 or any(
                            not isinstance(item, str) or not item.strip() for item in report[key]):
                        raise Rejected("incomplete_report")
                for key in ("observed_behavior", "external_impact", "investigation_scope", "interpretation", "detection"):
                    if not isinstance(report[key], str) or not report[key].strip():
                        raise Rejected("incomplete_report")
            status = {"publish": "APPROVED_FOR_PUBLICATION", "do_not_disclose": "NOT_DISCLOSING", "escalate": "ESCALATED"}[decision]
            # Approval is not publication. This method performs no network operation.
            review = {"reviewer": reviewer, "decision": decision, "security_reviewed": security_reviewed,
                      "third_party_notified": third_party_notified, "rationale": rationale, "timestamp": self.clock()}
            db.execute("UPDATE incidents SET status=?,review=?,public_report=? WHERE id=?",
                       (status, canonical(review).decode(), canonical(report).decode() if report is not None else None, incident_id))
            self.store.append(db, row["task"], reviewer, "disclosure_decision",
                              {"incident_id": incident_id, "decision": decision, "rationale_sha256": digest(rationale.encode()),
                               "report_sha256": digest(canonical(report)) if report is not None else None})

    def confirm_publication(self, incident_id: str, *, operator: str, publication_reference: str) -> None:
        """Record an operator-attested publication receipt; does not send a report."""
        identifier(operator)
        text(publication_reference, 1000)
        if not publication_reference.strip():
            raise Rejected("publication_reference_required")
        with self.store.transaction() as db:
            row = self._get_incident(db, incident_id)
            if row["status"] != "APPROVED_FOR_PUBLICATION":
                raise Rejected("publication_not_approved")
            review = loads(row["review"])
            review["publication_reference"] = publication_reference
            review["publication_attested_by"] = operator
            db.execute("UPDATE incidents SET status='PUBLISHED',review=? WHERE id=?",
                       (canonical(review).decode(), incident_id))
            self.store.append(db, row["task"], operator, "publication_attested",
                              {"incident_id": incident_id, "reference_sha256": digest(publication_reference.encode())})

    @staticmethod
    def _get_incident(db: sqlite3.Connection, incident_id: str) -> sqlite3.Row:
        identifier(incident_id)
        row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise Rejected("incident_not_found")
        return row
