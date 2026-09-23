"""Local control plane and a separately exposed JSON-lines agent data plane."""
from __future__ import annotations
import argparse
import getpass
import os
import secrets
import select
import shutil
import signal
import stat
import tempfile
import threading
import sqlite3
import sys
from pathlib import Path
from typing import Any

from ._version import __version__
from .configuration import read_config
from .reviewer_auth import AuthError
from .operations import backup_state, doctor, review_doctor, read_anchor, restore_state
from .protected import (check_state, no_symlink_components, private_directory, read_private as _read_private,
                        state_lease, sync_directory, write_private as _write_private)
from .broker import Broker
from .store import StoreBusy
from .tool_config import load_tools
from .codec import MAX_WIRE_BYTES, IntegrityError, Rejected, canonical, exact_keys, identifier, loads


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(canonical(value) + b'\n')
    sys.stdout.buffer.flush()


def _broker(state: Path, anchor_path: Path | None = None, *, adapters: bool = True) -> Broker:
    state = check_state(state)
    specs = loads(_read_private(state / 'tools.json')) if adapters and (state / 'tools.json').exists() else []
    return Broker(state / 'state.sqlite', _read_private(state / 'admin.key', limit=4096),
                  audit_anchor=read_anchor(anchor_path), tools=load_tools(specs))


def _password(path: Path | None, *, confirm: bool = False) -> str:
    if path is not None:
        return _read_private(path, limit=1025).decode('utf-8').removesuffix('\n').removesuffix('\r')
    if not sys.stdin.isatty():
        raise ValueError('Use a private --password-file for non-interactive provisioning or login')
    password = getpass.getpass('Reviewer password: ')
    if confirm and password != getpass.getpass('Confirm password: '):
        raise ValueError('Password confirmation does not match')
    return password


def initialize(state: Path, config_path: Path, *, production: bool = False,
               reviewer: tuple[str, str] | None = None) -> dict[str, Any]:
    """Validate first; publish a fully initialized directory in one rename."""
    config, tools = read_config(config_path, production=production)
    state = no_symlink_components(state)
    def check_empty_destination():
        # An owned EMPTY directory may start 0755: the private staged directory
        # replaces it atomically. Never adopt a foreign-owned destination.
        no_symlink_components(state)
        if state.exists():
            info = state.lstat()
            if (not stat.S_ISDIR(info.st_mode) or
                    (os.name == 'posix' and info.st_uid != os.geteuid()) or any(state.iterdir())):
                raise ValueError('Initialization requires an empty directory owned by the service user')
    check_empty_destination()
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix='.aeg-init-', dir=state.parent))
    try:
        key = secrets.token_bytes(32)
        _write_private(scratch / 'admin.key', key)
        _write_private(scratch / 'tools.json', canonical(config.get('tools', [])))
        broker = Broker(scratch / 'state.sqlite', key, tools=tools)
        try:
            tokens = broker.create_task(config['task_id'], config['tenant_id'], config['policy'])
            (scratch / 'sessions').mkdir(mode=0o700)
            for agent, token in tokens.items():
                _write_private(scratch / 'sessions' / (agent + '.token'), token.encode('ascii'))
            for source in config['sources']:
                broker.register_source(config['task_id'], source['id'], source['version'], source['document'],
                                       origin=source['origin'], origin_kind=source.get('origin_kind', 'operator_import'))
            if reviewer is not None:
                from .reviewer_auth import ReviewerAuth
                ReviewerAuth(broker.store).set_user(reviewer[0], reviewer[1], [config['task_id']])
            head = broker.store.verify()
        finally:
            broker.close()
        sync_directory(scratch / 'sessions')
        sync_directory(scratch)
        check_empty_destination()
        os.rename(scratch, state)  # POSIX replaces an empty directory, never populated state.
        sync_directory(state.parent)
        return {'initialized': True, 'task_id': config['task_id'], 'agents': list(tokens),
                'audit_head': head, 'tools': list(tools), 'package_version': __version__}
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise


def serve(b: Broker, token: str, stop: threading.Event | None = None) -> None:
    """Bounded JSONL framing; SIGTERM drains one active action, then exits.

    Only newline delimits a frame. Neither a partial frame nor an oversized frame
    prevents idle shutdown. stdout is protocol data, not an application log.
    """
    stop = stop or threading.Event()
    fd = sys.stdin.buffer.fileno()
    buffer = bytearray()
    discarding = False
    while not stop.is_set():
        readable, _, _ = select.select([fd], [], [], 0.2)
        if not readable:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            if discarding or buffer:
                _emit(b.handle(token, b'x' * (MAX_WIRE_BYTES + 1) if discarding else bytes(buffer)))
            return
        buffer.extend(chunk)
        while True:
            index = buffer.find(b'\n')
            if index == -1:
                break
            line = bytes(buffer[:index + 1])
            del buffer[:index + 1]
            oversized = discarding or len(line) > MAX_WIRE_BYTES
            _emit(b.handle(token, b'x' * (MAX_WIRE_BYTES + 1) if oversized else line))
            discarding = False
            if stop.is_set():
                return
        if len(buffer) > MAX_WIRE_BYTES:
            discarding = True
            buffer.clear()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='agent-effect-gate', description='Agent Effect Gate: mediated tools and auditable answers')
    parser.add_argument('--version', action='version', version=f'agent-effect-gate {__version__}')
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init', help='Trusted operator: create a NEW protected state directory')
    init.add_argument('--state', type=Path, required=True)
    init.add_argument('--config', type=Path, required=True)
    init.add_argument('--production', action='store_true')
    validate = commands.add_parser('validate-config', help='Validate operator config without creating state or making tool calls')
    validate.add_argument('--config', type=Path, required=True)
    validate.add_argument('--production', action='store_true')
    check = commands.add_parser('doctor', help='Operator-only local readiness checks; no endpoint requests')
    check.add_argument('--state', type=Path, required=True)
    check.add_argument('--anchor', type=Path)
    check.add_argument('--production', action='store_true')
    check.add_argument('--check-sandbox', action='store_true')
    backup = commands.add_parser('backup', help='Quiesced CLI-state backup; contains unencrypted secrets')
    backup.add_argument('--state', type=Path, required=True)
    backup.add_argument('--destination', type=Path, required=True)
    backup.add_argument('--anchor', type=Path)
    restore = commands.add_parser('restore', help='Restore into NEW state, with tasks suspended and pending approvals revoked')
    restore.add_argument('--backup', type=Path, required=True)
    restore.add_argument('--state', type=Path, required=True)
    restore.add_argument('--anchor', type=Path, required=True)
    restore.add_argument('--operator', required=True)
    rootfs = commands.add_parser('build-rootfs', help='Build the clean, operator-owned Linux code-execution rootfs')
    rootfs.add_argument('--destination', type=Path, required=True)
    setup = commands.add_parser('setup', help='Create customer state with networking, isolated code and a reviewer login')
    setup.add_argument('--state', type=Path, required=True)
    setup.add_argument('--rootfs', type=Path, required=True)
    setup.add_argument('--task-id', default='customer-task')
    setup.add_argument('--tenant-id', default='customer')
    setup.add_argument('--reviewer', required=True)
    setup.add_argument('--password-file', type=Path, help='Private password file for automated provisioning; otherwise prompt securely')
    setup.add_argument('--require-code-approval', action='store_true', help='Require human review for each code job instead of standing scoped authority')
    for name in ('reviewer-add', 'reviewer-disable', 'compact'):
        cmd = commands.add_parser(name)
        cmd.add_argument('--state', type=Path, required=True)
        if name == 'compact':
            cmd.add_argument('--anchor', type=Path)
        else:
            cmd.add_argument('--username', required=True)
        if name == 'reviewer-add':
            cmd.add_argument('--task', action='append', required=True, help='An explicit permitted task; repeat for more tasks')
            cmd.add_argument('--password-file', type=Path)
    for name in ('mcp', 'review', 'model-run'):
        cmd = commands.add_parser(name)
        cmd.add_argument('--state', type=Path, required=True)
        cmd.add_argument('--anchor', type=Path)
        cmd.add_argument('--production', action='store_true')
        cmd.add_argument('--check-sandbox', action='store_true')
        if name != 'review':
            cmd.add_argument('--agent', default='main')
        if name == 'review':
            cmd.add_argument('--host', default='127.0.0.1')
            cmd.add_argument('--port', type=int, default=8765)
            cmd.add_argument('--public-origin', help='Exact browser origin. Required for HTTPS reverse proxies.')
            cmd.add_argument('--tls-cert', type=Path)
            cmd.add_argument('--tls-key', type=Path)
        if name == 'model-run':
            cmd.add_argument('--model', required=True, help='Model identifier available in the operator account; no implicit paid default')
            cmd.add_argument('--prompt-file', type=Path, required=True)
            cmd.add_argument('--credential-env', default='OPENAI_API_KEY')
            cmd.add_argument('--allow-provider-egress', action='store_true', help='Authorize disclosure of task context and results to api.openai.com')
            cmd.add_argument('--max-steps', type=int, default=20)
            cmd.add_argument('--max-output-tokens', type=int, default=4096)
            cmd.add_argument('--checkpoint', type=Path, help='Private run file; defaults to STATE/runs/AGENT.json')
            cmd.add_argument('--resume', action='store_true', help='Resume the exact saved broker request')
    for name in ['serve', 'serve-unix', 'audit', 'incidents', 'report', 'triage', 'approve-release', 'review-tool', 'approve-tool', 'revoke-tool', 'suspend', 'resume']:
        p = commands.add_parser(name)
        p.add_argument('--state', type=Path, required=True)
        if name == 'serve-unix':
            p.add_argument('--socket', type=Path, required=True)
            p.add_argument('--allow-uid', type=int, action='append', required=True)
            p.add_argument('--group-access', action='store_true')
            p.add_argument('--max-workers', type=int, default=16)
        if name == 'serve':
            p.add_argument('--agent', required=True)
        if name in {'serve', 'serve-unix'}:
            p.add_argument('--production', action='store_true', help='Require successful production readiness checks before reading actions')
            p.add_argument('--check-sandbox', action='store_true', help='Run a harmless configured sandbox startup probe')
            p.add_argument('--anchor', type=Path, help='Previously retained external journal head')
        if name == 'audit': p.add_argument('--anchor', type=Path)
        if name == 'incidents': p.add_argument('--task')
        if name == 'report': p.add_argument('--incident', required=True)
        if name == 'triage':
            p.add_argument('--incident', required=True); p.add_argument('--owner', required=True)
            p.add_argument('--track', choices=['ready', 'minor', 'larger'], required=True)
            p.add_argument('--due-at', type=float, required=True, help='Operator-selected Unix timestamp')
            p.add_argument('--severity', choices=['low', 'medium', 'high', 'critical', 'unassessed'], required=True)
            p.add_argument('--third-party', choices=['yes', 'no', 'unknown'], default='unknown')
        if name == 'approve-release':
            p.add_argument('--proposal', required=True); p.add_argument('--reviewer', required=True)
            p.add_argument('--password-file', type=Path)
            p.add_argument('--break-glass', action='store_true', help='Explicit trusted-operator override, separately audited as breakglass')
            p.add_argument('--ttl', type=int)
        if name in {'review-tool', 'approve-tool', 'revoke-tool'}:
            p.add_argument('--call', required=True)
            if name != 'review-tool':
                p.add_argument('--reviewer', required=True)
                p.add_argument('--password-file', type=Path)
                p.add_argument('--break-glass', action='store_true', help='Explicit trusted-operator override, separately audited as breakglass')
            if name == 'approve-tool': p.add_argument('--ttl', type=int)
        if name in {'suspend', 'resume'}:
            p.add_argument('--task', required=True); p.add_argument('--operator', required=True)
    recovery = commands.add_parser('reconcile', help='Quiesced operator: record an independently verified uncertain effect outcome; never redispatch')
    recovery.add_argument('--state', type=Path, required=True)
    recovery.add_argument('--anchor', type=Path)
    recovery.add_argument('--kind', choices=['tool', 'release'], required=True)
    recovery.add_argument('--id', required=True)
    recovery.add_argument('--outcome', choices=['succeeded', 'failed'], required=True)
    recovery.add_argument('--operator', required=True)
    recovery.add_argument('--evidence-reference', required=True, help='Externally retained incident/receipt reference; only its digest enters the journal')
    client_run = commands.add_parser('model-client' , help='Checkpointed model runtime over a scoped Unix broker client')
    client_run.add_argument('--socket', type=Path, required=True)
    client_run.add_argument('--token-file', type=Path, required=True)
    client_run.add_argument('--broker-uid', type=int, default=os.geteuid())
    client_run.add_argument('--model', required=True)
    client_run.add_argument('--prompt-file', type=Path, required=True)
    client_run.add_argument('--credential-env', default='OPENAI_API_KEY')
    client_run.add_argument('--allow-provider-egress', action='store_true')
    client_run.add_argument('--max-steps', type=int, default=20)
    client_run.add_argument('--max-output-tokens', type=int, default=4096)
    client_run.add_argument('--checkpoint', type=Path, required=True)
    client_run.add_argument('--resume', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'model-client':
            from .client import GateClient
            from .model_connector import OpenAIResponsesAdapter
            from .models import RunCheckpoint, run_client
            with args.prompt_file.open('rb') as stream:
                prompt = stream.read(65537).decode('utf-8')
            adapter = OpenAIResponsesAdapter(model=args.model, prompt=prompt,
                allow_provider_egress=args.allow_provider_egress, credential_env=args.credential_env,
                max_output_tokens=args.max_output_tokens)
            client = GateClient.unix(args.socket, args.token_file, expected_server_uid=args.broker_uid)
            result = run_client(adapter, client, max_steps=args.max_steps,
                                checkpoint=RunCheckpoint(args.checkpoint), resume=args.resume)
            _emit(result)
            return 3 if result.get('status') == 'failed' else (4 if result.get('status') or not result.get('ok') else 0)
        if args.command == 'build-rootfs':
            from .rootfs import build
            _emit(build(args.destination)); return 0
        if args.command == 'setup':
            from .customer import customer_profile
            from .reviewer_auth import ReviewerAuth
            from .sandbox import LinuxSandbox
            if os.geteuid() == 0:
                raise ValueError('Customer setup must run under the dedicated non-root service account')
            password = _password(args.password_file, confirm=True)
            identifier(args.reviewer)
            if len(password) < 16:
                raise ValueError('Reviewer password must have at least 16 characters')
            profile = customer_profile(str(args.rootfs.absolute()), task_id=args.task_id, tenant_id=args.tenant_id)
            if args.require_code_approval:
                profile['policy']['tool_grants']['compute']['approval'] = 'required'
            # Code is enabled, not silently disabled when isolation is unavailable.
            sandbox = LinuxSandbox(str(args.rootfs.absolute()))
            probe = sandbox.invoke({'language': 'python', 'code': 'print("aeg-sandbox-ready")',
                                    'inputs': {}, 'input_sha256': {}, 'outputs': []}, 'operator-preflight')
            if not probe.succeeded or probe.text.strip() != 'aeg-sandbox-ready':
                raise ValueError('Customer setup requires a working Linux sandbox')
            with tempfile.TemporaryDirectory(prefix='aeg-config-') as temporary:
                config = Path(temporary) / 'customer.json'
                config.write_bytes(canonical(profile))
                result = initialize(args.state, config, production=True, reviewer=(args.reviewer, password))
            result.update(reviewer=args.reviewer, profile='customer', networking='scoped HTTPS enabled',
                          code_execution='isolated Linux sandbox enabled',
                          code_approval=profile['policy']['tool_grants']['compute']['approval'])
            _emit(result); return 0
        if args.command == 'init':
            _emit(initialize(args.state, args.config, production=args.production)); return 0
        if args.command == 'validate-config':
            config, tools = read_config(args.config, production=args.production)
            _emit({'valid': True, 'production': args.production, 'task_id': config['task_id'],
                   'tools': list(tools), 'side_effects_performed': False})
            return 0
        if args.command == 'backup':
            _emit(backup_state(args.state, args.destination, anchor=read_anchor(args.anchor)))
            return 0
        if args.command == 'restore':
            _emit(restore_state(args.backup, args.state, anchor=read_anchor(args.anchor), operator=args.operator))
            return 0
        with state_lease(args.state, exclusive=args.command in {'compact', 'reconcile'}):
            if args.command == 'doctor':
                result = doctor(args.state, anchor=read_anchor(args.anchor), production=args.production,
                                check_sandbox=args.check_sandbox)
                _emit(result)
                return 0 if result['ready'] else 2
            if args.command in {'serve', 'serve-unix', 'mcp', 'review', 'model-run'} and args.production:
                readiness_check = review_doctor if args.command == 'review' else doctor
                readiness = readiness_check(args.state, anchor=read_anchor(args.anchor), production=True,
                                            check_sandbox=args.check_sandbox)
                if not readiness['ready']:
                    raise ValueError('Production readiness checks failed; run doctor for details')
            b = _broker(args.state, getattr(args, 'anchor', None),
                        adapters=args.command in {'serve', 'serve-unix', 'mcp', 'model-run'})
            try:
                if args.command in {'reviewer-add', 'reviewer-disable'}:
                    from .reviewer_auth import ReviewerAuth
                    auth = ReviewerAuth(b.store)
                    if args.command == 'reviewer-add':
                        auth.set_user(args.username, _password(args.password_file, confirm=True), args.task)
                    else:
                        auth.disable(args.username)
                    _emit({'ok': True, 'username': args.username, 'action': args.command})
                elif args.command == 'reconcile':
                    _emit(b.reconcile_effect(args.kind, args.id, outcome=args.outcome,
                                             operator=args.operator, evidence_reference=args.evidence_reference))
                elif args.command == 'compact':
                    b.store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    b.store.db.execute('VACUUM')
                    b.store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    _emit({'compacted': True, 'audit_head': b.store.verify(), 'audit_history_deleted': False})
                elif args.command == 'review':
                    from .reviewer_web import ReviewerApp
                    try:
                        import uvicorn
                    except ImportError:
                        raise ValueError('Install the review optional dependency') from None
                    if not 1 <= args.port <= 65535 or bool(args.tls_cert) != bool(args.tls_key):
                        raise ValueError('Invalid listener or incomplete TLS configuration')
                    if args.host not in {'127.0.0.1', '::1', 'localhost'} and not args.tls_cert:
                        raise ValueError('Remote listeners require TLS; otherwise bind a loopback reverse-proxy backend')
                    if args.tls_key:
                        from .protected import private_file
                        private_file(args.tls_key)
                    origin_host = '[' + args.host + ']' if ':' in args.host else args.host
                    origin = args.public_origin or ('https' if args.tls_cert else 'http') + f'://{origin_host}:{args.port}'
                    app = ReviewerApp(b, public_origin=origin)
                    if args.tls_cert and not app.secure:
                        raise ValueError('TLS listener requires an HTTPS public origin')
                    if not b.store.db.execute('SELECT 1 FROM reviewer_users WHERE disabled=0 LIMIT 1').fetchone():
                        raise ValueError('Provision a reviewer account before starting the console')
                    uvicorn.run(app, host=args.host, port=args.port, access_log=False, server_header=False,
                                proxy_headers=False, limit_concurrency=32, timeout_keep_alive=5,
                                ssl_certfile=str(args.tls_cert) if args.tls_cert else None,
                                ssl_keyfile=str(args.tls_key) if args.tls_key else None)
                elif args.command == 'model-run':
                    from .model_connector import OpenAIResponsesAdapter
                    from .runtime import run
                    identifier(args.agent)
                    token = _read_private(args.state / 'sessions' / (args.agent + '.token')).decode('ascii')
                    with args.prompt_file.open('rb') as stream:
                        prompt = stream.read(65537).decode('utf-8')
                    adapter = OpenAIResponsesAdapter(model=args.model, prompt=prompt,
                        allow_provider_egress=args.allow_provider_egress, credential_env=args.credential_env,
                        max_output_tokens=args.max_output_tokens)
                    from .models import RunCheckpoint
                    checkpoint_path = args.checkpoint
                    if checkpoint_path is None:
                        directory = args.state / 'runs'
                        directory.mkdir(mode=0o700, exist_ok=True)
                        private_directory(directory)
                        checkpoint_path = directory / (args.agent + '.json')
                    result = run(adapter, b, token, max_steps=args.max_steps,
                                 checkpoint=RunCheckpoint(checkpoint_path), resume=args.resume)
                    _emit(result)
                    if result.get('runtime', {}).get('status') == 'failed':
                        return 3
                    if result.get('runtime', {}).get('status') == 'paused':
                        return 4
                elif args.command == 'serve-unix':
                    from .ipc import UnixGateServer
                    stop = threading.Event()
                    previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
                    server = None
                    try:
                        server = UnixGateServer(args.socket, b, allowed_uids=set(args.allow_uid),
                            max_workers=args.max_workers, socket_mode=0o660 if args.group_access else 0o600).start()
                        while not stop.wait(0.2):
                            pass
                    finally:
                        if server is not None:
                            server.stop()
                        for sig, handler in previous.items():
                            signal.signal(sig, handler)
                elif args.command in {'serve', 'mcp'}:
                    identifier(args.agent)
                    token = _read_private(args.state / 'sessions' / (args.agent + '.token')).decode('ascii')
                    stop = threading.Event()
                    previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
                    try:
                        if args.command == 'mcp':
                            from .mcp_server import MCPServer, serve_mcp
                            serve_mcp(MCPServer(b, token), stop)
                        else:
                            serve(b, token, stop)
                    finally:
                        for sig, handler in previous.items():
                            signal.signal(sig, handler)
                elif args.command == 'audit':
                    anchor = read_anchor(args.anchor)
                    _emit({'verified': True, 'audit_head': b.store.verify(anchor)})
                elif args.command == 'incidents':
                    _emit({'incidents': b.list_incidents(args.task)})
                elif args.command == 'report':
                    _emit(b.disclosure_draft(args.incident))
                elif args.command == 'triage':
                    b.triage_incident(args.incident, owner=args.owner, track=args.track, due_at=args.due_at,
                                      severity=args.severity, third_party=args.third_party)
                    _emit({'triaged': True})
                elif args.command == 'review-tool':
                    _emit(b.review_tool(args.call))
                elif args.command in {'approve-release', 'approve-tool', 'revoke-tool'}:
                    from .reviewer_auth import ReviewerAuth
                    from .reviewer_service import ReviewerService
                    kind = 'release' if args.command == 'approve-release' else 'tool'
                    record_id = args.proposal if kind == 'release' else args.call
                    auth, reviewer = ReviewerAuth(b.store), None
                    if args.break_glass:
                        identifier(args.reviewer)
                        with b.store.transaction() as db:
                            row = b._proposal(db, record_id) if kind == 'release' else b._tool_call(db, record_id)
                            b.store.append(db, row['task'], 'breakglass', 'operator_break_glass',
                                           {'claimed_reviewer': args.reviewer, 'command': args.command, 'id': record_id})
                        identity = 'breakglass'
                    else:
                        _, reviewer = auth.login(args.reviewer, _password(args.password_file))
                        ReviewerService(b).detail(reviewer, kind, record_id)  # Scope check before approval.
                        identity = reviewer.username
                    try:
                        if args.command == 'approve-release':
                            _emit(b.approve_release(record_id, reviewer=identity, ttl_seconds=args.ttl))
                        elif args.command == 'approve-tool':
                            _emit(b.approve_tool(record_id, reviewer=identity, ttl_seconds=args.ttl))
                        else:
                            b.revoke_tool(record_id, reviewer=identity)
                            _emit({'call_id': record_id, 'state': 'REVOKED'})
                    finally:
                        if reviewer is not None:
                            auth.logout(reviewer)
                else:
                    b.set_suspended(args.task, args.command == 'suspend', operator=args.operator)
                    _emit({'suspended': args.command == 'suspend'})
            finally:
                b.close()
        return 0
    except BrokenPipeError:
        # The peer may disconnect after an effect is durably recorded. Do not
        # retry it or let a second interpreter-shutdown flush print a traceback.
        with open(os.devnull, 'wb') as null:
            os.dup2(null.fileno(), sys.stdout.fileno())
        return 0
    except (AuthError, Rejected, IntegrityError, StoreBusy, ValueError, TypeError, OSError, sqlite3.Error, EOFError) as exc:
        # Stable classifications only; no raw exceptions, paths, tokens, or data.
        code = ('storage_busy' if isinstance(exc, StoreBusy) else
                'integrity_error' if isinstance(exc, IntegrityError) else
                'storage_error' if isinstance(exc, sqlite3.Error) else
                'state_busy_or_io_error' if isinstance(exc, OSError) else 'invalid_configuration_or_request')
        sys.stderr.write(canonical({'ok': False, 'error': code,
            'message': 'Stopped safely. Check permissions, configuration, credentials, state lease and audit anchor.'}).decode() + '\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
