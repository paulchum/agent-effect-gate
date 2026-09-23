"""Inert, exact-byte reviewer previews. Never interpret uploaded content."""
from __future__ import annotations

import base64
import binascii
from .codec import IntegrityError, digest


def upload_preview(plan):
    try:
        raw = base64.b64decode(plan['payload_b64'], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise IntegrityError('Invalid prepared upload encoding') from exc
    if digest(raw) != plan.get('payload_sha256'):
        raise IntegrityError('Prepared upload digest mismatch')
    try:
        decoded = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        decoded = None
    return {'media_type': plan['media_type'], 'byte_length': len(raw),
            'sha256': digest(raw), 'data_b64': plan['payload_b64'],
            'encoding': 'utf-8' if decoded is not None else 'binary', 'text': decoded,
            'warning': 'Untrusted payload; display as inert text, never HTML or executable content.'}
