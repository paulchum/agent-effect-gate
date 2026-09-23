"""Bounded, strict JSON and domain-separated authentication primitives."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from typing import Any

MAX_WIRE_BYTES = 2_000_000
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z", re.ASCII)


class Rejected(Exception):
    """A stable, public error code. Never put untrusted content in this message."""


class IntegrityError(RuntimeError):
    """Protected state could not be authenticated. Stop using this broker."""


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Rejected("invalid_identifier")
    return value


def text(value: Any, limit: int = 4096) -> str:
    if not isinstance(value, str):
        raise Rejected("invalid_text")
    try:
        if len(value.encode("utf-8")) > limit:
            raise Rejected("invalid_text")
    except UnicodeError as exc:
        raise Rejected("invalid_text") from exc
    return value


def validate_json(value: Any, *, max_nodes: int = 100_000) -> None:
    stack = [(value, 0)]
    seen = 0
    while stack:
        node, depth = stack.pop()
        seen += 1
        if depth > 32 or seen > max_nodes:
            raise Rejected("json_too_complex")
        if isinstance(node, dict):
            if any(type(k) is not str for k in node):
                raise Rejected("invalid_json_key")
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
        elif node is None or type(node) in (str, int, bool):
            pass
        elif type(node) is float and math.isfinite(node):
            pass
        else:
            raise Rejected("invalid_json_value")


def canonical(value: Any) -> bytes:
    validate_json(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, RecursionError, OverflowError) as exc:
        raise Rejected("invalid_json") from exc


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_json_key")
        result[key] = value
    return result


def _bad_constant(_: str) -> None:
    raise Rejected("non_finite_number")


def loads(raw: str | bytes, *, limit: int = MAX_WIRE_BYTES) -> Any:
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeError as exc:
            raise Rejected("invalid_json") from exc
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise Rejected("request_too_large")
    try:
        result = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_bad_constant)
        validate_json(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Rejected("invalid_json") from exc


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def seal(key: bytes, domain: str, value: Any) -> str:
    return hmac.new(key, domain.encode("ascii") + b"\0" + canonical(value),
                    hashlib.sha256).hexdigest()


def authenticated(key: bytes, domain: str, value: Any, signature: str) -> bool:
    return isinstance(signature, str) and hmac.compare_digest(seal(key, domain, value), signature)


def exact_keys(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= value.keys():
        raise Rejected("invalid_schema")
    if value.keys() - required - (optional or set()):
        raise Rejected("invalid_schema")
    return value
