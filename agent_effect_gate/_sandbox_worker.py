"""Trusted namespace bootstrap, NOT a model-facing interpreter.

Executed by /usr/bin/unshare as a non-root HOST uid. Before any model code:
private mount+network+PID namespaces, clean read-only rootfs, bounded tmpfs,
chroot, no ambient credentials, no inherited broker FDs, capability drop,
no_new_privs, syscall restrictions and process/resource limits.
"""
from __future__ import annotations
import base64
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile
from process_io import capture


# Native x86_64 and aarch64 names; libseccomp omits names absent on the host.
# New kernel syscalls are denied unless this reviewed profile explicitly allows them.
ALLOWED_SYSCALLS = (
    'read', 'write', 'readv', 'writev', 'pread64', 'pwrite64', 'close', 'close_range',
    'open', 'openat', 'creat', 'lseek', 'stat', 'fstat', 'lstat', 'newfstatat', 'statx',
    'access', 'faccessat', 'faccessat2', 'readlink', 'readlinkat', 'getdents', 'getdents64',
    'getcwd', 'chdir', 'fchdir', 'mkdir', 'mkdirat', 'rmdir', 'unlink', 'unlinkat',
    'rename', 'renameat', 'renameat2', 'link', 'linkat', 'symlink', 'symlinkat',
    'chmod', 'fchmod', 'fchmodat', 'fchmodat2', 'umask', 'truncate', 'ftruncate',
    'utime', 'utimes', 'futimesat', 'utimensat', 'fsync', 'fdatasync', 'fstatfs', 'statfs',
    'mmap', 'mprotect', 'munmap', 'mremap', 'madvise', 'msync', 'mincore', 'brk',
    'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'rt_sigpending', 'rt_sigsuspend',
    'rt_sigtimedwait', 'sigaltstack', 'restart_syscall',
    'getpid', 'getppid', 'gettid', 'getuid', 'geteuid', 'getgid', 'getegid', 'getgroups',
    'getresuid', 'getresgid', 'getpgid', 'getpgrp', 'getsid', 'setsid', 'setpgid',
    'fork', 'vfork', 'execve', 'wait4', 'waitid', 'exit', 'exit_group', 'kill', 'tkill', 'tgkill',
    'set_tid_address', 'set_robust_list', 'get_robust_list', 'futex', 'futex_waitv', 'rseq',
    'pipe', 'pipe2', 'dup', 'dup2', 'dup3', 'fcntl', 'flock',
    'poll', 'ppoll', 'select', 'pselect6', 'epoll_create', 'epoll_create1', 'epoll_ctl',
    'epoll_wait', 'epoll_pwait', 'epoll_pwait2',
    'clock_gettime', 'clock_getres', 'clock_nanosleep', 'nanosleep', 'gettimeofday', 'time', 'times',
    'getrlimit', 'setrlimit', 'prlimit64', 'getrusage', 'sysinfo', 'uname', 'getrandom',
    'sched_yield', 'sched_getaffinity', 'sched_getparam', 'sched_getscheduler',
    'sched_get_priority_min', 'sched_get_priority_max', 'getpriority',
    'arch_prctl', 'membarrier', 'getcpu', 'fadvise64', 'sendfile', 'copy_file_range',
)


def lockdown():
    libc = ctypes.CDLL(None, use_errno=True)
    lib = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]; lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]; lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]; lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    class ArgCmp(ctypes.Structure):
        _fields_ = [('arg',ctypes.c_uint),('op',ctypes.c_uint),('a',ctypes.c_uint64),('b',ctypes.c_uint64)]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(ArgCmp)]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    allow = 0x7fff0000  # SCMP_ACT_ALLOW
    deny_action = 0x00050000 | errno.EPERM  # SCMP_ACT_ERRNO, default for every unknown call.
    ctx = lib.seccomp_init(deny_action)
    if not ctx: raise RuntimeError('seccomp unavailable')
    def rule(name, action=allow):
        nr = lib.seccomp_syscall_resolve_name(name.encode())
        if nr >= 0 and lib.seccomp_rule_add(ctx, action, nr, 0) != 0:
            raise RuntimeError('seccomp rule failed')
    for name in ALLOWED_SYSCALLS:
        rule(name)
    # Libc may try clone3 then fall back to the inspectable clone ABI.
    rule('clone3', 0x00050000 | errno.ENOSYS)
    nr = lib.seccomp_syscall_resolve_name(b'clone')
    if nr >= 0:
        # Ordinary fork/thread flags only. Namespace creation, ptrace inheritance,
        # CLONE_PARENT, CLONE_IO and all future/unknown flags are excluded.
        ordinary = (0xff | 0x100 | 0x200 | 0x400 | 0x800 | 0x4000 | 0x10000 |
                    0x40000 | 0x80000 | 0x100000 | 0x200000 | 0x400000 | 0x1000000)
        cmp = ArgCmp(0, 7, (~ordinary) & 0xffffffffffffffff, 0)
        if lib.seccomp_rule_add_array(ctx, allow, nr, 1, ctypes.byref(cmp)) != 0:
            raise RuntimeError('seccomp clone rule failed')
    # Only harmless terminal queries; no device-specific ioctl surface.
    nr = lib.seccomp_syscall_resolve_name(b'ioctl')
    if nr >= 0:
        for request in (0x5401, 0x5413, 0x541B, 0x5421):  # TCGETS, TIOCGWINSZ, FIONREAD, FIONBIO
            cmp = ArgCmp(1, 4, request, 0)  # SCMP_CMP_EQ
            if lib.seccomp_rule_add_array(ctx, allow, nr, 1, ctypes.byref(cmp)) != 0:
                raise RuntimeError('seccomp ioctl rule failed')
    def finish(uid=0, gid=0, *, clear_groups=False):
        if libc.prctl(38,1,0,0,0) != 0: raise RuntimeError('no_new_privs failed')
        if libc.prctl(4,0,0,0,0) != 0: raise RuntimeError('dumpable failed')
        # Drop the bounding set before clearing effective/permitted capabilities.
        for cap in range(64): libc.prctl(24,cap,0,0,0)
        if clear_groups:
            os.setgroups([])
        if os.getgroups():
            raise RuntimeError('Supplementary host groups must not reach model code')
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
        if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
            raise RuntimeError('Worker identity drop failed')
        class Header(ctypes.Structure):
            _fields_ = [('version',ctypes.c_uint32),('pid',ctypes.c_int)]
        class Data(ctypes.Structure):
            _fields_ = [('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
        header, data = Header(0x20080522,0), (Data*2)()
        if libc.capset(ctypes.byref(header),ctypes.byref(data)) != 0: raise RuntimeError('capability drop failed')
        if lib.seccomp_load(ctx) != 0: raise RuntimeError('seccomp installation failed')
        lib.seccomp_release(ctx)
    return finish


def main(job):
    # Load libseccomp before chroot. The broker and its keys never enter this process.
    finish_lockdown = lockdown()
    worker_uid, worker_gid = job['worker_namespace_uid'], job['worker_namespace_gid']
    def mapped_host_id(path, inner):
        for line in Path(path).read_text().splitlines():
            inside, outside, count = map(int, line.split())
            if inside <= inner < inside + count:
                return outside + inner - inside
        raise RuntimeError('Missing worker identity mapping')
    if (mapped_host_id('/proc/self/uid_map', worker_uid) != job['expected_host_uid'] or
            mapped_host_id('/proc/self/gid_map', worker_gid) != job['expected_host_gid']):
        raise RuntimeError('Incorrect worker identity mapping')
    rootfs = Path(job['rootfs'])
    scratch = job['scratch']
    root = Path(scratch)/'root'; root.mkdir()
    def mount(*args):
        subprocess.run(['/usr/bin/mount', *map(str,args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    mount('--bind', rootfs, root)
    mount('-o','remount,bind,ro,nosuid,nodev', root)
    mount('-t','tmpfs','-o','size=16777216,nr_inodes=256,nosuid,nodev','tmpfs',root/'work')
    mount('-t','tmpfs','-o','size=8388608,nr_inodes=256,nosuid,nodev','tmpfs',root/'tmp')
    mount('--bind','/dev/null',root/'dev/null')
    # All peer processes in this PID namespace are also chrooted before the
    # untrusted child exists. /proc is intentionally absent, not host-mounted.
    os.chroot(root); os.chdir('/work')
    os.environ.clear(); os.environ.update(PATH='/usr/bin:/bin', HOME='/work', LANG='C.UTF-8', TMPDIR='/tmp', PYTHONDONTWRITEBYTECODE='1')
    os.chown('/work', worker_uid, worker_gid)
    os.chown('/tmp', worker_uid, worker_gid)
    for name, raw in job['inputs'].items():
        Path(name).write_bytes(base64.b64decode(raw,validate=True))
        os.chown(name, worker_uid, worker_gid)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(job['memory_bytes'],job['memory_bytes']))
    resource.setrlimit(resource.RLIMIT_FSIZE,(1_048_576,1_048_576))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    resource.setrlimit(resource.RLIMIT_NPROC,(job['process_limit'],job['process_limit']))
    cpu = max(1,math.ceil(job['timeout_seconds']))
    resource.setrlimit(resource.RLIMIT_CPU,(cpu,cpu))
    finish_lockdown(worker_uid, worker_gid, clear_groups=job['clear_supplementary_groups'])
    argv = ['/usr/bin/python3','-I','-B','-c',job['code']] if job['language']=='python' else ['/bin/sh','-c',job['code']]
    result = capture(argv, timeout=job['timeout_seconds'], max_output=job['max_output_bytes'], env=dict(os.environ))
    outputs, output_errors = {}, {}
    for name in job['outputs']:
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > job['max_output_bytes']:
                raise ValueError('Unsafe output')
            raw = os.read(fd,job['max_output_bytes']+1)
            if len(raw)>job['max_output_bytes']: raise ValueError('Large output')
            outputs[name] = {'data_b64':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
        except (OSError,ValueError):
            output_errors[name]='output_missing_or_unsafe'
        finally:
            if fd is not None: os.close(fd)
    # PID namespace destruction removes all descendants and tmpfs mounts.
    return {**result,'stdout':result['stdout'].decode('utf-8','replace'),
            'stderr':result['stderr'].decode('utf-8','replace'), 'outputs':outputs,'output_errors':output_errors,
            'isolation':'linux-user-mount-pid-net-ipc-uts+chroot+seccomp'}

if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(1_500_001)
        if len(raw)>1_500_000: raise ValueError('job too large')
        job = json.loads(raw)
        result = main(job)
    except BaseException:
        result = {'error':'sandbox_setup_or_supervision_failed'}
    sys.stdout.write(json.dumps(result,ensure_ascii=True)+'\n')
    sys.stdout.flush()
