"""Execute real Python or POSIX shell in fresh Linux namespaces, never in the broker.

Requires util-linux unshare/mount, libseccomp, unprivileged user namespaces, and an
operator-built clean rootfs. No fallback to unsandboxed subprocess execution exists.
"""
from __future__ import annotations
import base64
import os
import platform
import pwd
import shutil
import re
import tempfile
from pathlib import Path
from dataclasses import dataclass
from .codec import Rejected, canonical, digest, exact_keys, identifier, loads, text
from .tool_types import ToolResult
from .process_io import capture

def _subordinate_id(path: str, requested: int | None, current: int) -> int:
    """Resolve one administrator-delegated ID, never the broker's own ID.

    newuidmap/newgidmap independently enforce these assignments at launch.
    This preliminary check exists to fail configuration clearly, not to replace
    the kernel or the privileged mapping helpers' authorization checks.
    """
    if requested is not None and (type(requested) is not int or not 0 < requested < 2**32 - 1 or requested == current):
        raise ValueError('The sandbox worker must have a distinct non-root host identity')
    owner = os.geteuid()
    try:
        names = {str(owner), pwd.getpwuid(owner).pw_name}
        lines = Path(path).read_text(encoding='ascii').splitlines()
    except (OSError, KeyError, UnicodeError) as exc:
        raise ValueError('Configure subordinate worker IDs in /etc/subuid and /etc/subgid') from exc
    for line in lines:
        parts = line.split(':')
        if len(parts) != 3 or parts[0] not in names:
            continue
        try:
            start, count = int(parts[1]), int(parts[2])
        except ValueError:
            continue
        if not (0 < start < 2**32 - 1 and 0 < count and start + count <= 2**32 - 1):
            continue
        candidate = requested if requested is not None else start
        if start <= candidate < start + count and candidate != current:
            return candidate
    raise ValueError('No distinct delegated sandbox worker ID is configured')


@dataclass(frozen=True)
class LinuxSandbox:
    rootfs: str
    timeout_seconds: int = 5
    memory_bytes: int = 134217728
    process_limit: int = 16
    max_output_bytes: int = 65536
    worker_uid: int | None = None
    worker_gid: int | None = None

    def __post_init__(self):
        if platform.system() != 'Linux' or platform.machine() not in {'x86_64','aarch64'}:
            raise ValueError('This backend supports Linux x86_64/aarch64 only')
        if not isinstance(self.rootfs, str):
            raise ValueError('Rootfs must be an absolute path string')
        root = Path(self.rootfs)
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ValueError('Configure a protected absolute rootfs path')
        if not (root/'.aeg-rootfs.json').is_file():
            raise ValueError('Build a clean rootfs using scripts/build_rootfs.py')
        for name, low, high in [('timeout_seconds',1,20),('memory_bytes',67108864,1073741824),
                                ('process_limit',4,32),('max_output_bytes',1024,65536)]:
            if type(getattr(self,name)) is not int or not low <= getattr(self,name) <= high:
                raise ValueError('Invalid sandbox limit')
        if os.geteuid() == 0:
            uid = 65534 if self.worker_uid is None else self.worker_uid
            gid = 65534 if self.worker_gid is None else self.worker_gid
            if type(uid) is not int or not 0 < uid < 2**32 - 1 or type(gid) is not int or not 0 < gid < 2**32 - 1:
                raise ValueError('A root broker MUST launch a non-root host worker')
        else:
            uid = _subordinate_id('/etc/subuid', self.worker_uid, os.geteuid())
            gid = _subordinate_id('/etc/subgid', self.worker_gid, os.getegid())
            if not shutil.which('newuidmap', path='/usr/bin:/bin') or not shutil.which('newgidmap', path='/usr/bin:/bin'):
                raise ValueError('Non-root sandbox requires the administrator-installed newuidmap/newgidmap helpers')
        object.__setattr__(self,'worker_uid',uid); object.__setattr__(self,'worker_gid',gid)

    def manifest(self):
        # Hash the rootfs content manifest and the trusted worker implementation.
        # Protect the actual rootfs files from host-side edits; kernel reads are not
        # rehashed per invocation. The builder never imports application secrets.
        root = Path(self.rootfs)
        return {'adapter':'linux-sandbox-v2','effect':'local_code',
                'rootfs_manifest_sha256':digest((root/'.aeg-rootfs.json').read_bytes()),
                'bootstrap_sha256':digest(Path(__file__).with_name('_sandbox_worker.py').read_bytes()),
                'io_supervisor_sha256':digest(Path(__file__).with_name('process_io.py').read_bytes()),
                'timeout_seconds':self.timeout_seconds,'memory_bytes_per_process':self.memory_bytes,
                'process_limit_per_host_uid':self.process_limit,'max_output_bytes':self.max_output_bytes,
                'network':'none; use mediated HTTP tools separately','host_uid':self.worker_uid,
                'host_gid':self.worker_gid,'host_identity_separated':True,
                'syscall_policy':'default-deny-allowlist-v1',
                'arguments':{'language':'python or sh','code':'source text','inputs':'filename to artifact_id object',
                             'outputs':'up to four simple output filenames'}}

    def prepare(self, arguments, artifact):
        exact_keys(arguments,{'language','code','inputs','outputs'})
        if not isinstance(arguments['language'],str) or arguments['language'] not in {'python','sh'}:
            raise Rejected('language_not_allowed')
        code = text(arguments['code'],32768)
        if not isinstance(arguments['inputs'],dict) or len(arguments['inputs'])>16:
            raise Rejected('invalid_inputs')
        if not isinstance(arguments['outputs'],list) or len(arguments['outputs'])>4:
            raise Rejected('invalid_outputs')
        def name_ok(name):
            if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',name):
                raise Rejected('path_not_allowed')
        inputs, hashes = {}, {}
        for name, artifact_id in arguments['inputs'].items():
            name_ok(name)
            payload, media_type, sha = artifact(identifier(artifact_id))
            inputs[name] = base64.b64encode(payload).decode(); hashes[name] = sha
        for name in arguments['outputs']: name_ok(name)
        if sum(len(x) for x in inputs.values())>750000:
            raise Rejected('tool_request_too_large')
        return {'language':arguments['language'],'code':code,'inputs':inputs,'input_sha256':hashes,'outputs':arguments['outputs']}

    def invoke(self, prepared, call_id):
        job = {**prepared,'rootfs':self.rootfs,'timeout_seconds':self.timeout_seconds,
               'memory_bytes':self.memory_bytes,'process_limit':self.process_limit,'max_output_bytes':self.max_output_bytes}
        worker = Path(__file__).with_name('_sandbox_worker.py')
        if os.geteuid() == 0:
            mapping = ['--map-root-user']
            job['worker_namespace_uid'] = job['worker_namespace_gid'] = 0
            job['clear_supplementary_groups'] = False  # Popen clears them on the host.
        else:
            # Map only the trusted bootstrap and one delegated worker identity.
            # Do NOT use --map-root-user here: it permanently denies setgroups,
            # preventing the bootstrap from dropping inherited host groups.
            # The comma spelling also supports util-linux before 2.39.
            mapping = [f'--map-users={os.geteuid()},0,1', f'--map-users={self.worker_uid},1,1',
                       f'--map-groups={os.getegid()},0,1', f'--map-groups={self.worker_gid},1,1',
                       '--setgroups=allow']
            job['worker_namespace_uid'] = job['worker_namespace_gid'] = 1
            job['clear_supplementary_groups'] = True
        job['expected_host_uid'] = self.worker_uid
        job['expected_host_gid'] = self.worker_gid
        argv = ['/usr/bin/unshare','--user', *mapping, '--mount','--pid','--fork','--net','--ipc','--uts',
                '--kill-child=SIGKILL','--propagation','private','/usr/bin/python3','-I',str(worker)]
        # -I removes script-directory imports, so bootstrap an explicit trusted
        # path before importing the helper. This is host code, NOT model code.
        bootstrap = 'import sys,runpy;sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name="__main__")'
        argv = argv[:-1] + ['-c',bootstrap,str(worker.parent),str(worker)]
        kw = {'env':{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/tmp'}}
        if os.geteuid()==0:
            kw.update(user=self.worker_uid,group=self.worker_gid,extra_groups=[])
        with tempfile.TemporaryDirectory(prefix='aeg-run-') as scratch:
            if os.geteuid() == 0:
                os.chown(scratch, self.worker_uid, self.worker_gid)
            job['scratch'] = scratch
            result = capture(argv, canonical(job), timeout=self.timeout_seconds+10, max_output=750000, **kw)
        if result['returncode']!=0 or result['stop_reason']:
            return ToolResult({'error':'sandbox_unavailable_or_stopped','stop_reason':result['stop_reason']},'',False)
        data = loads(result['stdout'],limit=750000)
        if not isinstance(data,dict) or 'error' in data:
            return ToolResult({'error':'sandbox_setup_or_supervision_failed'},'',False)
        transcript = data['stdout'] + ('\n[stderr]\n'+data['stderr'] if data['stderr'] else '')
        succeeded = data['returncode']==0 and data['stop_reason'] is None and not data['output_errors']
        return ToolResult(data, transcript, succeeded)
