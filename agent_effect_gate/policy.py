"""Operator-authored contracts; the model cannot create or modify them."""
from __future__ import annotations

import math
from typing import Any

from .codec import Rejected, canonical, exact_keys, identifier, loads, text

DEFAULTS = {
    "answer_mode": "model",
    "fields": [],
    "tool_grants": {},
    "max_observation_bytes": 16_000_000,
    "local_only": True,
    "destinations": [],
    "channels": [],
    "max_requests": 1000,
    "max_read_requests": 2000,
    "max_retry_requests": 1000,
    "max_tool_plan_bytes": 16_000_000,
    "max_artifact_bytes": 262144,
    "max_total_artifact_bytes": 2097152,
    "max_message_bytes": 4096,
    "max_messages": 100,
    "max_denials": 20,
    "approval_ttl_seconds": 300,
    "stage": "testing",
    "model_family": "operator-not-specified",
}


def validate_policy(raw: dict[str, Any]) -> dict[str, Any]:
    exact_keys(raw, {"agents"}, set(DEFAULTS))
    p = loads(canonical({**DEFAULTS, **raw}))  # Detach all caller-owned mutable objects.
    if not isinstance(p["answer_mode"], str) or p["answer_mode"] not in {"model", "evidence"}:
        raise Rejected("invalid_answer_mode")
    if not isinstance(p["tool_grants"], dict) or len(p["tool_grants"]) > 32:
        raise Rejected("invalid_tool_grants")
    for tool_id, grant in p["tool_grants"].items():
        identifier(tool_id)
        exact_keys(grant, {"approval", "max_calls"}, {"allow_argument_egress"})
        if not isinstance(grant["approval"], str) or grant["approval"] not in {"required", "standing"}:
            raise Rejected("invalid_tool_approval")
        if type(grant["max_calls"]) is not int or not 1 <= grant["max_calls"] <= 10000:
            raise Rejected("invalid_limit")
        grant.setdefault("allow_argument_egress", False)
        if type(grant["allow_argument_egress"]) is not bool:
            raise Rejected("invalid_tool_grants")
    if type(p["local_only"]) is not bool:
        raise Rejected("invalid_policy")
    if not isinstance(p["agents"], list) or not 1 <= len(p["agents"]) <= 32:
        raise Rejected("invalid_agents")
    for agent in p["agents"]:
        identifier(agent)
    if len(set(p["agents"])) != len(p["agents"]):
        raise Rejected("duplicate_agent")
    if not isinstance(p["destinations"], list) or len(p["destinations"]) > 32:
        raise Rejected("invalid_destinations")
    for destination in p["destinations"]:
        identifier(destination)
    if p["local_only"] and p["destinations"]:
        raise Rejected("local_policy_has_destinations")
    if not isinstance(p["channels"], list) or len(p["channels"]) > 256:
        raise Rejected("invalid_channels")
    for edge in p["channels"]:
        if not isinstance(edge, list) or len(edge) != 2 or any(a not in p["agents"] for a in edge):
            raise Rejected("invalid_channel")
        if edge[0] == edge[1]:
            raise Rejected("invalid_channel")
    limits = {
        "max_observation_bytes": (1_000_000, 1_000_000_000),
        "max_read_requests": (1, 100000),
        "max_retry_requests": (1, 100000), "max_tool_plan_bytes": (1024, 100_000_000),
        "max_requests": (1, 100000), "max_artifact_bytes": (1, 524288),
        "max_total_artifact_bytes": (1, 16777216), "max_message_bytes": (1, 32768),
        "max_messages": (1, 10000), "max_denials": (1, 1000),
        "approval_ttl_seconds": (1, 3600),
    }
    for name, (low, high) in limits.items():
        if type(p[name]) is not int or not low <= p[name] <= high:
            raise Rejected("invalid_limit")
    if not isinstance(p["stage"], str) or p["stage"] not in {"training", "evaluation", "testing", "deployment"}:
        raise Rejected("invalid_stage")
    text(p["model_family"], 100)
    if not isinstance(p["fields"], list) or not (1 if p["answer_mode"] == "evidence" else 0) <= len(p["fields"]) <= 100:
        raise Rejected("invalid_fields")
    ids: set[str] = set()
    for f in p["fields"]:
        exact_keys(f, {"id", "label", "source", "version", "pointer"},
                   {"operation", "expected_sha256", "where", "columns"})
        identifier(f["id"])
        identifier(f["source"])
        identifier(f["version"])
        text(f["label"], 200)
        pointer = text(f["pointer"], 1000)
        if pointer and not pointer.startswith("/"):
            raise Rejected("invalid_pointer")
        if f["id"] in ids:
            raise Rejected("duplicate_field")
        ids.add(f["id"])
        f.setdefault("operation", "identity")
        if not isinstance(f["operation"], str) or f["operation"] not in {"identity", "sum", "mean", "count", "filter_table"}:
            raise Rejected("invalid_operation")
        sha = f.get("expected_sha256")
        if sha is not None and (not isinstance(sha, str) or len(sha) != 64 or
                                any(c not in "0123456789abcdef" for c in sha)):
            raise Rejected("invalid_digest")
        if f["operation"] == "filter_table":
            exact_keys(f.get("where"), {"column", "comparison", "value"})
            identifier(f["where"]["column"])
            if not isinstance(f["where"]["comparison"], str) or f["where"]["comparison"] not in {"gt", "ge", "eq", "lt", "le"}:
                raise Rejected("invalid_comparison")
            v = f["where"]["value"]
            if type(v) not in (int, float) or not math.isfinite(v):
                raise Rejected("invalid_threshold")
            if not isinstance(f.get("columns"), list) or not 1 <= len(f["columns"]) <= 32:
                raise Rejected("invalid_columns")
            for col in f["columns"]:
                identifier(col)
        elif "where" in f or "columns" in f:
            raise Rejected("invalid_transform")
    return p


def json_pointer(data: Any, pointer: str) -> Any:
    node = data
    if not pointer:
        return node
    for raw_token in pointer[1:].split("/"):
        # Reject malformed RFC 6901 escapes rather than silently choosing another key.
        import re
        if re.search(r"~(?![01])", raw_token):
            raise Rejected("invalid_pointer")
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isascii() and token.isdecimal() and (token == "0" or not token.startswith("0")):
            index = int(token)
            if index >= len(node):
                raise Rejected("source_field_missing")
            node = node[index]
        else:
            raise Rejected("source_field_missing")
    return node


def evaluate(data: Any, field: dict[str, Any]) -> Any:
    """Only operator-declared transformations; never eval or model-authored code."""
    value = json_pointer(data, field["pointer"])
    operation = field["operation"]
    if operation == "identity":
        return value
    if not isinstance(value, list):
        raise Rejected("source_type_mismatch")
    if operation == "count":
        return len(value)
    if operation in {"sum", "mean"}:
        if any(type(n) not in (int, float) for n in value):
            raise Rejected("source_type_mismatch")
        if operation == "mean" and not value:
            raise Rejected("empty_mean")
        try:
            result = sum(value) if all(type(n) is int for n in value) else math.fsum(value)
            if operation == "mean":
                result /= len(value)
            if isinstance(result, float) and not math.isfinite(result):
                raise Rejected("non_finite_result")
            return result
        except (OverflowError, ValueError) as exc:
            raise Rejected("non_finite_result") from exc
    if operation == "filter_table":
        where = field["where"]
        comparisons = {"gt": lambda a, b: a > b, "ge": lambda a, b: a >= b,
                       "eq": lambda a, b: a == b, "lt": lambda a, b: a < b,
                       "le": lambda a, b: a <= b}
        out = []
        for row in value:
            if not isinstance(row, dict) or any(c not in row for c in field["columns"]):
                raise Rejected("source_type_mismatch")
            n = row.get(where["column"])
            if type(n) not in (int, float):
                raise Rejected("source_type_mismatch")
            if comparisons[where["comparison"]](n, where["value"]):
                out.append({c: row[c] for c in field["columns"]})
        return out
    raise Rejected("invalid_operation")
