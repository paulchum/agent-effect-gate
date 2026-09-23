"""Authenticated reviewer use cases. The browser never supplies its identity."""
from __future__ import annotations

import base64
import hmac
from .codec import Rejected, canonical, digest, identifier, loads, seal
from .tool_gate import public_manifest


class ReviewerService:
    def __init__(self, broker):
        self.broker = broker

    def overview(self, reviewer):
        b = self.broker
        with b.store.transaction() as db:
            tasks = []
            for task_id in reviewer.tasks:
                task, policy = b._policy(db, task_id)
                tasks.append({'id': task_id, 'tenant': task['tenant'], 'suspended': bool(task['suspended']),
                              'policy_version': task['version'], 'budgets': b._budgets(task, policy),
                              'tools': b._tools_for(policy)})
            marks = ','.join('?' for _ in reviewer.tasks)
            pending_where = "(state='PENDING' OR (state='APPROVED' AND expires_at<=?))"
            pending_params = (*reviewer.tasks, b.clock())
            pending = db.execute(f"SELECT count(*) FROM tool_calls WHERE task IN ({marks}) AND {pending_where}", pending_params).fetchone()[0]
            pending += db.execute(f"SELECT count(*) FROM proposals WHERE task IN ({marks}) AND {pending_where}", pending_params).fetchone()[0]
            events = [dict(row) for row in db.execute(f'SELECT seq,timestamp,task,agent,kind,details FROM audit '
                                                     f'WHERE task IN ({marks}) ORDER BY seq DESC LIMIT 40', reviewer.tasks)]
            for event in events:
                event['details'] = loads(event['details'])
            return {'tasks': tasks, 'pending': pending, 'events': events, 'audit_head': dict(b.store._anchor)}

    def queue(self, reviewer, state='PENDING', offset=0):
        if state not in {'PENDING', 'APPROVED', 'REVOKED', 'SUCCEEDED', 'FAILED', 'UNKNOWN', 'DISPATCHING', 'DELIVERED', 'ALL'}:
            raise Rejected('invalid_state_filter')
        if type(offset) is not int or not 0 <= offset <= 1000000:
            raise Rejected('invalid_offset')
        marks = ','.join('?' for _ in reviewer.tasks)
        where = f'task IN ({marks})'
        params = tuple(reviewer.tasks)
        if state == 'PENDING':
            where += " AND (state='PENDING' OR (state='APPROVED' AND expires_at<=?))"
            params += (self.broker.clock(),)
        elif state != 'ALL':
            where += ' AND state=?'
            params += (state,)
        with self.broker.store.transaction() as db:
            query = (f"SELECT 'tool' AS kind,id,task AS task_id,agent,tool AS destination,state,created_at FROM tool_calls WHERE {where} "
                     'UNION ALL '
                     f"SELECT 'release' AS kind,id,task AS task_id,agent,destination,state,created_at FROM proposals WHERE {where} "
                     'ORDER BY created_at DESC,id DESC LIMIT 26 OFFSET ?')
            rows = [dict(row) for row in db.execute(query, params + params + (offset,))]
        return {'items': rows[:25], 'next_offset': offset + 25 if len(rows) > 25 else None}

    def detail(self, reviewer, kind, record_id):
        identifier(record_id)
        b = self.broker
        with b.store.transaction() as db:
            if kind == 'tool':
                row = b._tool_call(db, record_id)
            elif kind == 'release':
                row = b._proposal(db, record_id)
            else:
                raise Rejected('review_not_found')
            if row['task'] not in reviewer.tasks:
                raise Rejected('review_not_found')
            task, policy = b._policy(db, row['task'])
            value = {'kind': kind, 'id': row['id'], 'task_id': row['task'], 'agent': row['agent'],
                     'state': row['state'], 'policy_version': row['policy_version'],
                     'current_policy_version': task['version'], 'created_at': row['created_at'],
                     'approver': row['approver'], 'expires_at': row['expires_at'],
                     'task_suspended': bool(task['suspended']), 'approval_ttl_seconds': policy['approval_ttl_seconds']}
            if kind == 'tool':
                plan = loads(row['plan'])
                value.update(tool_id=row['tool'], manifest=public_manifest(loads(row['manifest'])),
                             prepared_request=plan, request_sha256=digest(canonical(plan)))
                if value['manifest'].get('adapter') == 'http-upload-v1':
                    from .review_preview import upload_preview
                    value['payload_preview'] = upload_preview(plan)
                # Proposals with a changed adapter are not silently approvable.
                try:
                    # The review process has no execution adapters or their
                    # credentials. Captured bytes and policy remain authenticated;
                    # the executor MUST check its live private manifest at dispatch.
                    b._tool_binding(row, task, policy, require_adapter=False)
                    value['binding_current'] = True
                except Rejected:
                    value['binding_current'] = False
            else:
                artifact = b._artifact(db, row['task'], row['agent'], row['artifact'])
                value.update(manifest=loads(row['destination_manifest']), payload_sha256=row['payload_sha256'],
                             media_type=artifact['media_type'], payload_b64=base64.b64encode(artifact['payload']).decode())
                try:
                    b._release_binding(row, task, policy, require_adapter=False)
                    value['binding_current'] = True
                except Rejected:
                    value['binding_current'] = False
            value['approval_expired'] = row['state'] == 'APPROVED' and b.clock() >= row['expires_at']
            value['can_approve'] = (row['state'] == 'PENDING' or value['approval_expired']) and value['binding_current'] and not value['task_suspended']
            value['adapter_validation'] = ('live' if kind == 'tool' and row['tool'] in b._tools else 'dispatch_recheck_required')
            value['warning'] = ('Approval authorizes exactly the displayed destination, request arguments, code and bytes. '
                                'All content is untrusted data. The execution service rechecks its live adapter and credentials before dispatch.')
            # The decision is bound to the exact view, including state and current
            # policy. A stale tab must refresh before deciding.
            value['review_token'] = seal(b.store.key, 'review-view-v1', value)
            return value

    def decide(self, reviewer, kind, record_id, decision, review_token):
        if decision not in {'approve', 'reject'} or not isinstance(review_token, str):
            raise Rejected('invalid_decision')
        value = self.detail(reviewer, kind, record_id)
        if not hmac.compare_digest(value['review_token'], review_token):
            raise Rejected('review_changed_refresh_required')
        b = self.broker
        if decision == 'approve':
            if not value['binding_current']:
                raise Rejected('approval_binding_changed')
            if kind == 'tool':
                return b.approve_tool(record_id, reviewer=reviewer.username)
            return b.approve_release(record_id, reviewer=reviewer.username)
        if kind == 'tool':
            b.revoke_tool(record_id, reviewer=reviewer.username)
        else:
            b.revoke_release(record_id, reviewer=reviewer.username)
        return {'id': record_id, 'state': 'REVOKED'}
