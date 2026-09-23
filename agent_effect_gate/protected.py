"""Filesystem checks for operator-owned state, never an agent workspace.

These checks do not replace isolation from processes running as the service UID
or protection of parent directories against untrusted replacement.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path


def no_symlink_components(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError('Protected paths must not contain symlinks')
    return path


def _owner_and_mode(info: os.stat_result) -> None:
    if os.name == 'posix':
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Protected state must be private and owned by the service user')


def private_directory(path: Path) -> Path:
    path = no_symlink_components(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('Protected directory is missing or unsafe')
    _owner_and_mode(info)
    return path


def private_file(path: Path) -> Path:
    path = no_symlink_components(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Protected files must be ordinary, single-link files')
    _owner_and_mode(info)
    return path


def read_private(path: Path, *, limit: int = 8_000_000) -> bytes:
    path = no_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Protected files must be ordinary, single-link files')
        _owner_and_mode(info)
        if info.st_size > limit:
            raise ValueError('Protected file exceeds its limit')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Protected file exceeds its limit')
        return data
    finally:
        os.close(fd)


def write_private(path: Path, content: bytes) -> None:
    no_symlink_components(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path: Path) -> None:
    if os.name != 'posix':
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_state(state: Path) -> Path:
    state = private_directory(state)
    private_file(state / 'state.sqlite')
    private_file(state / 'admin.key')
    private_directory(state / 'sessions')
    for name in ('tools.json', 'state.sqlite-wal', 'state.sqlite-shm', 'state.sqlite-journal'):
        path = state / name
        if os.path.lexists(path):
            try:
                private_file(path)
            except FileNotFoundError:
                # A SQLite sidecar may disappear when another connection closes.
                if not name.startswith('state.sqlite-'):
                    raise
    return state


from contextlib import contextmanager


@contextmanager
def state_lease(state: Path, *, exclusive: bool = False):
    """Coordinate CLI maintenance with long-lived CLI sessions on POSIX hosts.

    Direct Python integrations must separately quiesce their own broker objects.
    Never unlink the lease file: flock is attached to its inode.
    """
    if os.name != 'posix':
        raise ValueError('Protected CLI deployment requires a POSIX host')
    import fcntl
    state = private_directory(state)
    path = state / '.operator.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0) |
                 getattr(os, 'O_NONBLOCK', 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Unsafe state lease file')
        _owner_and_mode(info)
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)
