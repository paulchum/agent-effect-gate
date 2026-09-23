"""Strict OPERATOR config loader. Never expose this to an agent or model tool call."""
from __future__ import annotations
import os
from .codec import exact_keys, identifier, Rejected
from .http_tools import HTTPTransport, HTTPRead, HTTPUpload, GitHubCodeSearch


def load_tools(specs):
    if not isinstance(specs, list) or len(specs)>32:
        raise ValueError('Invalid tool configuration')
    out = {}
    for spec in specs:
        if not isinstance(spec,dict): raise ValueError('Invalid tool configuration')
        name = identifier(spec.get('id'))
        if name in out: raise ValueError('Duplicate tool name')
        kind = spec.get('kind')
        common = {'credential_env','timeout_seconds','max_response_bytes','ca_file','allow_loopback'}
        if kind == 'linux_sandbox':
            from .sandbox import LinuxSandbox
            exact_keys(spec,{'id','kind','rootfs'}, {'timeout_seconds','memory_bytes','process_limit','max_output_bytes','worker_uid','worker_gid'})
            out[name] = LinuxSandbox(**{k:v for k,v in spec.items() if k not in {'id','kind'}})
            continue
        if kind == 'http_read':
            exact_keys(spec,{'id','kind','origin','path_prefix','query_keys'},common)
        elif kind == 'http_upload':
            exact_keys(spec,{'id','kind','origin','path'},common)
        elif kind == 'github_code_search':
            exact_keys(spec,{'id','kind','repositories'}, {'credential_env','timeout_seconds','max_response_bytes'})
        else:
            raise ValueError('Unknown host adapter kind')
        token = None
        if 'credential_env' in spec:
            identifier(spec['credential_env'])
            token = os.environ.get(spec['credential_env'])
            if not token: raise ValueError('Required host credential is unavailable')
        options = {k:spec[k] for k in common-{'credential_env'} if k in spec}
        transport = HTTPTransport(spec.get('origin','https://api.github.com'),credential=token,**options)
        if kind == 'http_read':
            if not isinstance(spec['query_keys'],list): raise ValueError('query_keys must be a list')
            out[name] = HTTPRead(transport,spec['path_prefix'],tuple(spec['query_keys']))
        elif kind == 'http_upload': out[name] = HTTPUpload(transport,spec['path'])
        else:
            if not isinstance(spec['repositories'],list) or any(not isinstance(r, str) for r in spec['repositories']): raise ValueError('repositories must be strings')
            out[name] = GitHubCodeSearch(tuple(spec['repositories']),transport)
    return out
