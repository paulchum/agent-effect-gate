"""Usable customer profile: scoped HTTPS and isolated code are enabled."""
from __future__ import annotations
from .codec import identifier


def customer_profile(rootfs: str, *, task_id='customer-task', tenant_id='customer'):
    identifier(task_id); identifier(tenant_id)
    return {
        'task_id': task_id, 'tenant_id': tenant_id,
        'policy': {'agents': ['main'], 'stage': 'deployment', 'answer_mode': 'model',
                   'local_only': False, 'max_requests': 1000, 'max_read_requests': 2000,
                   'max_denials': 20, 'approval_ttl_seconds': 300,
                   'tool_grants': {
                       'python_docs': {'approval': 'standing', 'max_calls': 40, 'allow_argument_egress': True},
                       'compute': {'approval': 'standing', 'max_calls': 40}}},
        'sources': [],
        'tools': [
            {'id': 'python_docs', 'kind': 'http_read', 'origin': 'https://docs.python.org',
             'path_prefix': '/3', 'query_keys': [], 'timeout_seconds': 10, 'max_response_bytes': 65536},
            {'id': 'compute', 'kind': 'linux_sandbox', 'rootfs': rootfs,
             'timeout_seconds': 5, 'memory_bytes': 134217728, 'process_limit': 16, 'max_output_bytes': 65536}],
    }
