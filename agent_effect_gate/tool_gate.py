"""Mediated real tools and provenance-aware, model-authored answers.

Neither citations nor a tool's output prove the truth of a model's prose.
Tool observations are authenticated captures, explicitly untrusted as instructions.
"""
from __future__ import annotations
import secrets
import sqlite3
from typing import Any
from .codec import Rejected, IntegrityError, authenticated, canonical, digest, exact_keys, identifier, loads, seal, text
from .tool_types import ToolResult

TOOL_READS = {'list_tools', 'read_observation'}
TOOL_SCHEMAS = {
    'list_tools': set(),
    'propose_tool': {'tool_id', 'arguments'},
    'execute_tool': {'call_id'},
    'read_observation': {'observation_id'},
    'submit_answer': {'text', 'citations', 'limitations'},
}
TERMINAL = {'SUCCEEDED', 'FAILED', 'UNKNOWN', 'REVOKED'}
TOOL_SCHEMA = '''
CREATE TABLE IF NOT EXISTS tool_calls(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, agent TEXT NOT NULL,
 tool TEXT NOT NULL, policy_version INTEGER NOT NULL, manifest TEXT NOT NULL,
 plan TEXT NOT NULL, binding_mac TEXT NOT NULL, state TEXT NOT NULL,
 approver TEXT, expires_at REAL, approval_mac TEXT, observation TEXT,
 created_at REAL NOT NULL, FOREIGN KEY(task) REFERENCES tasks(id));
CREATE INDEX IF NOT EXISTS tool_calls_scope ON tool_calls(task,tool,state);
CREATE INDEX IF NOT EXISTS tool_calls_agent ON tool_calls(task,agent,created_at,id);
CREATE TABLE IF NOT EXISTS observations(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, agent TEXT NOT NULL, call_id TEXT NOT NULL,
 tool TEXT NOT NULL, document TEXT NOT NULL, text TEXT NOT NULL,
 sha256 TEXT NOT NULL, captured_at REAL NOT NULL, mac TEXT NOT NULL,
 FOREIGN KEY(task) REFERENCES tasks(id));
CREATE INDEX IF NOT EXISTS observations_scope ON observations(task,agent,captured_at,id);
CREATE TRIGGER IF NOT EXISTS observations_no_update BEFORE UPDATE ON observations
 BEGIN SELECT RAISE(ABORT, 'observation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS observations_no_delete BEFORE DELETE ON observations
 BEGIN SELECT RAISE(ABORT, 'observation is immutable'); END;
CREATE TABLE IF NOT EXISTS drafts(
 task TEXT NOT NULL, agent TEXT NOT NULL, policy_version INTEGER NOT NULL,
 document TEXT NOT NULL, mac TEXT NOT NULL, PRIMARY KEY(task,agent));
'''

def public_manifest(value):
    """Secret-derived bindings are host-only, including in old cached responses."""
    if isinstance(value, dict):
        return {k: public_manifest(v) for k, v in value.items()
                if k not in {'credential_binding', 'credential_sha256'}}
    if isinstance(value, list):
        return [public_manifest(v) for v in value]
    return value


class ToolGate:
    def _private_tool_manifest(self, adapter):
        """Bind rotation with a persistent, domain-separated keyed digest.

        Adapters may produce a private credential fingerprint. It is never stored
        as a bare guess-verifier in new proposals and never sent to the model.
        """
        def bind(value):
            if isinstance(value, dict):
                return {k: (seal(self.store.key, 'credential-binding-v1', {'value': v})
                            if k == 'credential_binding' and v is not None else bind(v))
                        for k, v in value.items()}
            if isinstance(value, list):
                return [bind(v) for v in value]
            return value
        return bind(loads(canonical(adapter.manifest())))

    def _tools_for(self, p: dict[str, Any]) -> list[dict[str, Any]]:
        return [{'tool_id': name, 'grant': grant,
                 'manifest': public_manifest(self._tools[name].manifest()) if name in self._tools else None}
                for name, grant in p.get('tool_grants', {}).items()]

    def _tool_call(self, db, call_id, task_id=None, agent=None):
        row = db.execute('SELECT * FROM tool_calls WHERE id=?', (identifier(call_id),)).fetchone()
        if row is None or (task_id is not None and row['task'] != task_id) or (agent is not None and row['agent'] != agent):
            raise Rejected('tool_call_not_found')
        binding = {k: row[k] for k in ('id','task','agent','tool','policy_version','created_at')}
        binding.update(manifest=loads(row['manifest']), plan=loads(row['plan']))
        if not authenticated(self.store.key, 'tool-call-v1', binding, row['binding_mac']):
            raise IntegrityError('Tool call authentication failed')
        return row

    def _tool_binding(self, row, task, p, *, require_adapter=True):
        grant = p.get('tool_grants', {}).get(row['tool'])
        if grant is None:
            raise Rejected('tool_not_allowed')
        adapter = self._tools.get(row['tool'])
        if adapter is None and require_adapter:
            raise Rejected('tool_unavailable')
        manifest = loads(row['manifest'])
        if manifest['effect'].startswith('network_') and p['local_only']:
            raise Rejected('local_only')
        if task['version'] != row['policy_version'] or (adapter is not None and self._private_tool_manifest(adapter) != manifest):
            raise Rejected('approval_binding_changed')
        return grant, adapter

    @staticmethod
    def _tool_status(row):
        return {'call_id': row['id'], 'tool_id': row['tool'], 'state': row['state'],
                'observation_id': row['observation'],
                'retry_dispatch': False,
                'outcome': 'unknown_or_in_progress' if row['state'] == 'DISPATCHING' else row['state'].lower()}

    def _recent_tools(self, db, task_id, agent):
        # Bounded snapshots. All observations remain individually addressable.
        rows = db.execute('SELECT id,tool,state,observation FROM tool_calls WHERE task=? AND agent=? '
                          'ORDER BY created_at DESC,id DESC LIMIT 50', (task_id, agent))
        return [self._tool_status(row) for row in rows]

    def review_tool(self, call_id: str) -> dict[str, Any]:
        """CONTROL PLANE: exact egress/code/input bytes; render only as inert data."""
        with self.store.transaction() as db:
            row = self._tool_call(db, call_id)
            value = {**self._tool_status(row), 'task_id': row['task'], 'agent': row['agent'],
                     'manifest': public_manifest(loads(row['manifest'])), 'prepared_request': loads(row['plan']),
                     'policy_version': row['policy_version'], 'binding_mac': row['binding_mac'],
                     'warning': 'Review the destination and EVERY argument/body byte, including GET query strings.'}
            if value['manifest'].get('adapter') == 'http-upload-v1':
                from .review_preview import upload_preview
                value['payload_preview'] = upload_preview(value['prepared_request'])
            return value

    def approve_tool(self, call_id: str, *, reviewer: str, ttl_seconds: int | None = None):
        identifier(reviewer)
        with self.store.transaction() as db:
            row = self._tool_call(db, call_id)
            task, p = self._policy(db, row['task'])
            if task['suspended']:
                raise Rejected('task_suspended')
            self._tool_binding(row, task, p, require_adapter=False)
            renewing = row['state'] == 'APPROVED' and self.clock() >= row['expires_at']
            if renewing:
                previous = {'call_id': row['id'], 'binding_mac': row['binding_mac'],
                            'reviewer': row['approver'], 'expires_at': row['expires_at']}
                if not authenticated(self.store.key, 'tool-approval-v1', previous, row['approval_mac']):
                    raise IntegrityError('Tool approval authentication failed')
            if row['state'] != 'PENDING' and not renewing:
                raise Rejected('proposal_not_pending')
            ttl = p['approval_ttl_seconds'] if ttl_seconds is None else ttl_seconds
            if type(ttl) is not int or not 1 <= ttl <= p['approval_ttl_seconds']:
                raise Rejected('invalid_approval_ttl')
            expires = self.clock() + ttl
            signed = {'call_id': row['id'], 'binding_mac': row['binding_mac'], 'reviewer': reviewer, 'expires_at': expires}
            db.execute("UPDATE tool_calls SET state='APPROVED',approver=?,expires_at=?,approval_mac=? WHERE id=?",
                       (reviewer, expires, seal(self.store.key, 'tool-approval-v1', signed), call_id))
            self.store.append(db, row['task'], reviewer, 'tool_approval_renewed' if renewing else 'tool_approved',
                              {'call_id': call_id, 'expires_at': expires})
            return {'call_id': call_id, 'state': 'APPROVED', 'expires_at': expires}

    def revoke_tool(self, call_id: str, *, reviewer: str):
        identifier(reviewer)
        with self.store.transaction() as db:
            row = self._tool_call(db, call_id)
            if row['state'] not in {'PENDING', 'APPROVED'}:
                raise Rejected('dispatch_already_started')
            db.execute("UPDATE tool_calls SET state='REVOKED' WHERE id=?", (call_id,))
            self.store.append(db, row['task'], reviewer, 'tool_revoked', {'call_id': call_id})

    def _dispatch_tool(self, db, task, p, agent, operation, a):
        task_id = task['id']
        if operation == 'list_tools':
            return {'tools': self._tools_for(p)}, None
        if operation == 'read_observation':
            return self._observation(db, task_id, agent, a['observation_id']), None
        if operation == 'submit_answer':
            if p.get('answer_mode', 'evidence') != 'model':
                raise Rejected('model_answer_not_enabled')
            body = {'text': text(a['text'], 65536), 'limitations': a['limitations'], 'citations': []}
            if not body['text'].strip():
                raise Rejected('empty_answer')
            if not isinstance(a['limitations'], list) or len(a['limitations']) > 30:
                raise Rejected('invalid_schema')
            for limitation in a['limitations']:
                text(limitation, 2000)
            if not isinstance(a['citations'], list) or len(a['citations']) > 50:
                raise Rejected('invalid_schema')
            for c in a['citations']:
                exact_keys(c, {'observation_id', 'quote'})
                quote = text(c['quote'], 4000)
                if not quote.strip():
                    raise Rejected('empty_citation')
                obs = self._observation(db, task_id, agent, c['observation_id'])
                if quote not in obs['text']:
                    raise Rejected('citation_quote_mismatch')
                body['citations'].append({'observation_id': obs['observation_id'], 'quote': quote,
                                          'sha256': obs['sha256'], 'tool_id': obs['tool_id'],
                                          'call_id': obs['call_id'], 'captured_at': obs['captured_at'],
                                          'provenance': obs['provenance']})
            signed = {'task': task_id, 'agent': agent, 'policy_version': task['version'], 'body': body}
            db.execute('INSERT INTO drafts VALUES(?,?,?,?,?) ON CONFLICT(task,agent) DO UPDATE SET '
                       'policy_version=excluded.policy_version,document=excluded.document,mac=excluded.mac',
                       (task_id, agent, task['version'], canonical(body).decode(), seal(self.store.key, 'draft-v1', signed)))
            return self._model_answer(db, task, p, agent), None
        if operation == 'propose_tool':
            tool_id = identifier(a['tool_id'])
            grant = p.get('tool_grants', {}).get(tool_id)
            if grant is None:
                raise Rejected('tool_not_allowed')
            adapter = self._tools.get(tool_id)
            if adapter is None:
                raise Rejected('tool_unavailable')
            manifest = self._private_tool_manifest(adapter)
            effect = manifest['effect']
            if effect.startswith('network_') and p['local_only']:
                raise Rejected('local_only')
            # Read requests are ALSO egress. Standing permission must say so.
            if effect == 'network_write' and grant['approval'] != 'required':
                raise Rejected('writes_require_exact_approval')
            if effect == 'network_read' and grant['approval'] == 'standing' and not grant['allow_argument_egress']:
                raise Rejected('argument_egress_not_authorized')
            def artifact(art_id):
                row = self._artifact(db, task_id, agent, identifier(art_id))
                return bytes(row['payload']), row['media_type'], row['sha256']
            plan = adapter.prepare(a['arguments'], artifact)
            raw = canonical(plan)
            if len(raw) > 1_000_000:
                raise Rejected('tool_request_too_large')
            used_plans = db.execute(
                'SELECT coalesce(sum(length(CAST(plan AS BLOB))),0) FROM tool_calls WHERE task=?',
                (task_id,)).fetchone()[0]
            if used_plans + len(raw) > p.get('max_tool_plan_bytes', 16_000_000):
                raise Rejected('tool_plan_quota_exceeded')
            call_id, now = 'call_' + secrets.token_hex(16), self.clock()
            binding = {'id': call_id, 'task': task_id, 'agent': agent, 'tool': tool_id,
                       'policy_version': task['version'], 'manifest': manifest, 'plan': plan, 'created_at': now}
            db.execute('INSERT INTO tool_calls(id,task,agent,tool,policy_version,manifest,plan,binding_mac,state,created_at) '
                       "VALUES(?,?,?,?,?,?,?,?, 'PENDING', ?)",
                       (call_id, task_id, agent, tool_id, task['version'], canonical(manifest).decode(), raw.decode(),
                        seal(self.store.key, 'tool-call-v1', binding), now))
            return {'call_id': call_id, 'state': 'PENDING', 'approval_required': grant['approval'] == 'required',
                    'request_sha256': digest(raw), 'manifest': public_manifest(manifest)}, None
        if operation == 'execute_tool':
            row = self._tool_call(db, a['call_id'], task_id, agent)
            if row['state'] in TERMINAL | {'DISPATCHING'}:
                result = self._tool_status(row)
                if row['observation']:
                    result['observation'] = self._observation(db, task_id, agent, row['observation'])
                return result, None
            grant, adapter = self._tool_binding(row, task, p)
            if grant['approval'] == 'required':
                if row['state'] != 'APPROVED':
                    raise Rejected('approval_required')
                signed = {'call_id': row['id'], 'binding_mac': row['binding_mac'], 'reviewer': row['approver'], 'expires_at': row['expires_at']}
                if not authenticated(self.store.key, 'tool-approval-v1', signed, row['approval_mac']):
                    raise IntegrityError('Tool approval authentication failed')
                if self.clock() >= row['expires_at']:
                    raise Rejected('approval_expired')
            used = db.execute("SELECT count(*) FROM tool_calls WHERE task=? AND tool=? AND state IN "
                              "('DISPATCHING','SUCCEEDED','FAILED','UNKNOWN')", (task_id, row['tool'])).fetchone()[0]
            if used >= grant['max_calls']:
                raise Rejected('tool_budget_exhausted')
            # Reserve worst-case observation space for concurrent invocations.
            size = db.execute('SELECT coalesce(sum(length(document)+length(text)),0) FROM observations WHERE task=?', (task_id,)).fetchone()[0]
            active = db.execute("SELECT count(*) FROM tool_calls WHERE task=? AND state='DISPATCHING'", (task_id,)).fetchone()[0]
            if size + (active + 1) * 1_000_000 > p.get('max_observation_bytes', 16_000_000):
                raise Rejected('observation_quota_exceeded')
            db.execute("UPDATE tool_calls SET state='DISPATCHING' WHERE id=?", (row['id'],))
            self.store.append(db, task_id, agent, 'tool_dispatch_intent', {'call_id': row['id'], 'binding_mac': row['binding_mac']})
            return self._tool_status(self._tool_call(db, row['id'])), {'kind': 'tool', 'id': row['id'], 'adapter': adapter, 'plan': loads(row['plan']),
                                                                'effect': loads(row['manifest'])['effect']}
        raise Rejected('unknown_operation')

    def _deliver_tool(self, job, task_id, agent, request_id, fingerprint):
        from .store import StoreBusy
        outcome, state = None, 'UNKNOWN'
        try:
            outcome = job['adapter'].invoke(job['plan'], job['id'])
            if not isinstance(outcome, ToolResult) or type(outcome.succeeded) is not bool:
                raise ValueError('Invalid adapter result')
            text(outcome.text, 500_000)
            if len(canonical(outcome.data)) + len(outcome.text.encode('utf-8')) > 1_000_000:
                raise ValueError('Oversized observation')
            state = 'SUCCEEDED' if outcome.succeeded else 'FAILED'
        except Exception:
            # Secrets from exception strings never enter model-visible state.
            outcome = None
            if job.get('effect') == 'network_read':
                # A failed read has no unconfirmed external write to reconcile.
                # It still consumes this call's budget and is NEVER auto-replayed.
                state = 'FAILED'
                outcome = ToolResult({'error': 'tool_read_failed'}, '', False)
        try:
            with self.store.transaction() as db:
                row = self._tool_call(db, job['id'], task_id, agent)
                obs_id = None
                if outcome is not None:
                    obs_id, now = 'obs_' + secrets.token_hex(16), self.clock()
                    raw = canonical(outcome.data).decode()
                    sha = digest(canonical({'data': outcome.data, 'text': outcome.text}))
                    signed = {'id': obs_id, 'task': task_id, 'agent': agent, 'call_id': row['id'],
                              'tool': row['tool'], 'sha256': sha, 'captured_at': now}
                    db.execute('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)',
                               (obs_id, task_id, agent, row['id'], row['tool'], raw, outcome.text,
                                sha, now, seal(self.store.key, 'observation-v1', signed)))
                db.execute("UPDATE tool_calls SET state=?,observation=? WHERE id=? AND state='DISPATCHING'", (state, obs_id, row['id']))
                event = self.store.append(db, task_id, agent, 'tool_result', {'call_id': row['id'], 'state': state, 'observation_id': obs_id})
                if state != 'SUCCEEDED':
                    self._incident(db, task_id, 'tool_outcome_unknown' if state == 'UNKNOWN' else 'tool_failed', event, severity='medium')
                result = self._tool_status(self._tool_call(db, row['id']))
                if obs_id:
                    result['observation'] = self._observation(db, task_id, agent, obs_id)
                response = {'ok': True, 'result': result}
                db.execute('UPDATE requests SET response=? WHERE task=? AND agent=? AND id=? AND request_sha256=?',
                           (canonical({'ok': True}).decode(), task_id, agent, request_id, fingerprint))
            return response
        except StoreBusy:
            return {'ok': False, 'error': 'post_dispatch_audit_unavailable', 'delivery_outcome': 'unknown',
                    'call_id': job['id'], 'retryable': False, 'retry_dispatch': False}
        except (sqlite3.Error, IntegrityError, OSError):
            self._failed = True
            return {'ok': False, 'error': 'post_dispatch_audit_unavailable', 'delivery_outcome': 'unknown',
                    'call_id': job['id'], 'action_execution_stopped': True}

    def _observation(self, db, task_id, agent, observation_id):
        row = db.execute('SELECT * FROM observations WHERE id=? AND task=? AND agent=?',
                         (identifier(observation_id), task_id, agent)).fetchone()
        if row is None:
            raise Rejected('observation_not_found')
        data = loads(row['document'])
        signed = {k: row[k] for k in ('id','task','agent','call_id','tool','sha256','captured_at')}
        if digest(canonical({'data': data, 'text': row['text']})) != row['sha256'] or not authenticated(self.store.key, 'observation-v1', signed, row['mac']):
            raise IntegrityError('Observation authentication failed')
        call = self._tool_call(db, row['call_id'], task_id, agent)
        manifest, plan = loads(call['manifest']), loads(call['plan'])
        provenance = {'adapter': manifest['adapter'], 'origin': manifest.get('transport', {}).get('origin', 'isolated-local-code'),
                      'target': plan.get('target'), 'request_sha256': digest(canonical(plan)), 'tool_state': call['state']}
        return {'provenance': provenance, 'observation_id': row['id'], 'call_id': row['call_id'], 'tool_id': row['tool'],
                'data': data, 'text': row['text'], 'sha256': row['sha256'], 'captured_at': row['captured_at'],
                'trust': 'untrusted_tool_output', 'truthfulness_verified': False}

    def _model_answer(self, db, task, p, agent):
        row = db.execute('SELECT * FROM drafts WHERE task=? AND agent=?', (task['id'], agent)).fetchone()
        body = {'text': None, 'citations': [], 'limitations': []}
        status = 'awaiting_model_answer'
        if row:
            body = loads(row['document'])
            signed = {'task': task['id'], 'agent': agent, 'policy_version': row['policy_version'], 'body': body}
            if not authenticated(self.store.key, 'draft-v1', signed, row['mac']):
                raise IntegrityError('Draft authentication failed')
            status = 'submitted' if row['policy_version'] == task['version'] else 'stale_policy'
        answer = {'format': 'agent-effect-gate-model-answer-v1', 'task_id': task['id'], 'policy_version': task['version'],
                  **body, 'status': status, 'model_authored': True, 'truthfulness_verified': False,
                  'citation_check': 'Captured observation and exact quote only; no semantic entailment guarantee.',
                  'notices': self._notices(db, task['id']), 'releases': self._releases(db, task['id']),
                  'tool_calls': self._recent_tools(db, task['id'], agent), 'suspended': bool(task['suspended'])}
        return {'answer': answer, 'mac': seal(self.store.key, 'answer-v1', answer)}
