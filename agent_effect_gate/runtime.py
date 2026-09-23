"""Provider-neutral loop. Model prose is submitted through an auditable final envelope."""
from __future__ import annotations
from typing import Any, Protocol
from .broker import Broker
from .codec import Rejected, canonical, loads


class ModelAdapter(Protocol):
    def propose(self, context: dict[str, Any], last_result: dict[str, Any] | None) -> dict[str, Any] | str | bytes:
        """Return a JSON action envelope; no direct tool or authority access."""
        ...


def run(adapter: ModelAdapter, broker: Broker, session_token: str, *, max_steps: int = 20,
        checkpoint=None, resume: bool = False) -> dict[str, Any]:
    """Run a bounded session, return only a freshly broker-rendered final envelope.

    The adapter is trusted provider-integration code handling untrusted model output.
    It must not execute generated code, dispatch independent tools, or stream model
    text directly to users. An adapter can be implemented for any model provider.
    """
    if type(max_steps) is not int or not 1 <= max_steps <= 1000:
        raise ValueError("max_steps must be between 1 and 1000")

    if checkpoint is not None or resume:
        return _run_checkpointed(adapter, broker, session_token, max_steps=max_steps, checkpoint=checkpoint, resume=resume)

    def host_call(operation: str) -> dict[str, Any]:
        return broker.host_view(session_token, operation)
    last = None
    task_id = None
    for _ in range(max_steps):
        view = host_call("context")
        if not view["ok"]:
            return view
        context = view["result"]["snapshot"]
        task_id = context["task_id"]
        if context["control"]["suspended"]:
            return host_call("answer")
        if context['control']['budgets']['actions']['remaining'] == 0:
            result = host_call('answer')
            result['runtime'] = {'status': 'paused', 'reason': 'request_budget_exhausted'}
            return result
        try:
            # The adapter receives detached data, no references to broker state.
            proposal = adapter.propose(loads(canonical(context), limit=8_000_000),
                                       loads(canonical(last), limit=8_000_000) if last is not None else None)
        except Exception:
            broker.record_runtime_notice(task_id, "model_adapter_failed")
            result = host_call('answer')
            result['runtime'] = {'status': 'failed', 'reason': 'model_adapter_failed'}
            return result
        last = broker.handle(session_token, proposal)
        action = None
        try:
            action = loads(proposal) if isinstance(proposal, (str, bytes)) else proposal
            wants_answer = isinstance(action, dict) and action.get("operation") in {"answer", "submit_answer"}
        except Rejected:
            wants_answer = False
        if wants_answer and last["ok"] and last.get("result", {}).get("answer", {}).get("status") != "awaiting_model_answer":
            # Refresh through the host-controlled gate; do not forward prior model text.
            return host_call("answer")
        if (isinstance(action, dict) and action.get('operation') in {'execute_tool', 'execute_release'} and
                last.get('result', {}).get('state') in {'UNKNOWN', 'DISPATCHING'}):
            result = host_call('answer')
            result['runtime'] = {'status': 'paused', 'reason': 'awaiting_reconciliation',
                                 'pending_request': action, 'last_result': last}
            return result
        if last.get('delivery_outcome') == 'unknown':
            result = host_call('answer')
            result['runtime'] = {'status': 'paused', 'reason': 'awaiting_reconciliation',
                                 'pending_request': action, 'last_result': last}
            return result
        if last.get('error') in {'approval_required', 'approval_expired', 'broker_busy', 'request_budget_exhausted', 'read_budget_exhausted',
                                'retry_budget_exhausted', 'tool_plan_quota_exceeded'}:
            result = host_call('answer')
            result['runtime'] = {'status': 'paused', 'reason': last['error'], 'last_result': last}
            return result
        if last.get("action_execution_stopped") or last.get("error") == "broker_stopped":
            return last
    if task_id is not None:
        broker.record_runtime_notice(task_id, "runtime_step_budget_exhausted")
    return host_call("answer")


class _TrustedHostClient:
    """Only constructed by trusted in-process host code; never exported via IPC."""
    def __init__(self, broker, token):
        self._broker, self._token = broker, token

    def request(self, operation, arguments, *, request_id):
        return self._broker.handle(self._token, {'request_id': request_id, 'operation': operation, 'arguments': arguments})

    def view(self, operation):
        return self._broker.host_view(self._token, operation)


def _run_checkpointed(adapter, broker, token, *, max_steps, checkpoint, resume):
    from .models import run_client
    result = run_client(adapter, _TrustedHostClient(broker, token), max_steps=max_steps,
                        checkpoint=checkpoint, resume=resume)
    if result.get('action_execution_stopped'):
        return result
    if 'answer' in result.get('result', {}) and not result.get('status'):
        return result
    reason = result.get('error') or result.get('status', 'runtime_paused')
    if reason in {'model_adapter_failed', 'runtime_step_budget_exhausted'}:
        view = broker.host_view(token, 'context')
        if view.get('ok'):
            broker.record_runtime_notice(view['result']['snapshot']['task_id'], reason)
    final = broker.host_view(token, 'answer')
    final['runtime'] = {'status': 'failed' if result.get('status') == 'failed' else 'paused',
                        'reason': reason, 'last_result': result,
                        'resume_available': checkpoint is not None}
    if result.get('pending_request') is not None:
        final['runtime']['pending_request'] = result['pending_request']
    return final
