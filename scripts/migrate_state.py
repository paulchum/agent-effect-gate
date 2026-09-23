#!/usr/bin/env python3
"""Copy stopped 0.1/0.2 protected state without rekeying; leave the source untouched."""
from __future__ import annotations
import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_effect_gate import Broker
from agent_effect_gate.codec import identifier


def private_copy(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError('Source must be an ordinary protected file')
    if os.name == 'posix' and source.stat().st_mode & 0o077:
        raise ValueError('Source key/config/token must have private permissions')
    with destination.open('xb') as output:
        os.chmod(destination, 0o600)
        output.write(source.read_bytes())


def migrate(source: Path, destination: Path, anchor: dict | None = None) -> dict:
    """Caller must stop old brokers; source DB is opened read-only, WAL via backup()."""
    source, destination = source.absolute(), destination.absolute()
    if source.is_symlink() or not source.is_dir() or destination.exists():
        raise ValueError('Use an existing ordinary source and a NEW destination')
    if source == destination or source in destination.parents:
        raise ValueError('Destination must be outside source state')
    db_source = source / 'state.sqlite'
    if db_source.is_symlink() or not db_source.is_file():
        raise ValueError('Source database is missing or not an ordinary file')
    scratch = Path(tempfile.mkdtemp(prefix='.aeg-migrate-', dir=destination.parent))
    try:
        os.chmod(scratch, 0o700)
        private_copy(source / 'admin.key', scratch / 'admin.key')
        sessions = source / 'sessions'
        if sessions.is_symlink() or not sessions.is_dir():
            raise ValueError('Protected sessions directory is missing')
        (scratch / 'sessions').mkdir(mode=0o700)
        for item in sessions.iterdir():
            if item.suffix != '.token':
                raise ValueError('Unexpected sessions entry')
            identifier(item.stem)
            private_copy(item, scratch / 'sessions' / item.name)
        if (source / 'tools.json').exists():
            private_copy(source / 'tools.json', scratch / 'tools.json')
        db_target = scratch / 'state.sqlite'
        with closing(sqlite3.connect(db_source.as_uri() + '?mode=ro', uri=True)) as old:
            with closing(sqlite3.connect(db_target)) as new:
                os.chmod(db_target, 0o600)
                old.backup(new)
        broker = Broker(db_target, (scratch / 'admin.key').read_bytes(), audit_anchor=anchor)
        try:
            head = broker.store.verify(anchor)
            tasks = broker.store.db.execute('SELECT count(*) FROM tasks').fetchone()[0]
        finally:
            broker.close()
        # No old state bytes, credentials, or source filenames are returned.
        os.rename(scratch, destination)
        return {'migrated': True, 'tasks': tasks, 'audit_head': head,
                'source_unchanged': True, 'sessions_and_key_preserved': True}
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--anchor', type=Path)
    args = parser.parse_args()
    try:
        anchor = json.loads(args.anchor.read_text()) if args.anchor else None
        print(json.dumps(migrate(args.source, args.destination, anchor), indent=2))
    except (ValueError, OSError, sqlite3.Error):
        raise SystemExit('Migration stopped. Check paths, permissions and journal integrity; source was not overwritten.')

if __name__ == '__main__':
    main()
