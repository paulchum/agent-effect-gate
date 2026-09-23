"""Side-effect-free deployment configuration validation (no tool invocation)."""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from .broker import Broker
from .codec import Rejected, canonical, exact_keys, identifier, loads
from .policy import validate_policy
from .tool_config import load_tools


def validate_grants(policy: dict[str, Any], tools: dict[str, Any], *, production: bool = False) -> None:
    if production and policy['stage'] != 'deployment':
        raise ValueError('Production policy must declare stage deployment')
    for name, grant in policy['tool_grants'].items():
        if name not in tools:
            raise ValueError('A granted tool is not registered')
        manifest = tools[name].manifest()
        effect = manifest['effect']
        if effect.startswith('network_') and policy['local_only']:
            raise ValueError('Local-only policy cannot grant network tools')
        if effect == 'network_write' and grant['approval'] != 'required':
            raise ValueError('Network writes require exact approval')
        if effect == 'network_read' and grant['approval'] == 'standing' and not grant['allow_argument_egress']:
            raise ValueError('Standing reads require explicit argument egress authority')
    if production:
        for adapter in tools.values():
            manifest = adapter.manifest()
            if manifest.get('transport', {}).get('loopback_test_mode'):
                raise ValueError('Production configuration cannot enable loopback fixtures')


def read_config(path: Path, *, production: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    with path.open('rb') as stream:
        config = loads(stream.read(8_000_001), limit=8_000_000)
    exact_keys(config, {'task_id', 'tenant_id', 'policy', 'sources'}, {'tools'})
    identifier(config['task_id'])
    identifier(config['tenant_id'])
    if not isinstance(config['sources'], list):
        raise Rejected('invalid_sources')
    policy = validate_policy(config['policy'])
    tools = load_tools(config.get('tools', []))
    validate_grants(policy, tools, production=production)
    if policy['destinations']:
        raise ValueError('Legacy sinks require a trusted Python integration, not CLI configuration')
    # Exercise exactly the same source and policy validation as initialization,
    # entirely in memory. No state files, outgoing calls, or code jobs are made.
    broker = Broker(':memory:', secrets.token_bytes(32), tools=tools)
    try:
        broker.create_task(config['task_id'], config['tenant_id'], policy)
        for source in config['sources']:
            exact_keys(source, {'id', 'version', 'document', 'origin'}, {'origin_kind'})
            broker.register_source(config['task_id'], source['id'], source['version'], source['document'],
                                   origin=source['origin'], origin_kind=source.get('origin_kind', 'operator_import'))
    finally:
        broker.close()
    config = loads(canonical({**config, 'policy': policy}), limit=8_000_000)
    return config, tools
