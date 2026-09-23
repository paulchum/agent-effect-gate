"""Host-owned adapters. Model arguments are data, never adapter registrations."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Protocol

ArtifactResolver = Callable[[str], tuple[bytes, str, str]]

@dataclass(frozen=True)
class ToolResult:
    data: Any
    text: str
    succeeded: bool = True

class ToolAdapter(Protocol):
    def manifest(self) -> dict[str, Any]:
        """Host-private authority, endpoint, version, limits and schema; never raw secrets.
        Credential fingerprints must use credential_binding so the broker can
        key the private value and omit it from every public manifest."""
        ...
    def prepare(self, arguments: dict[str, Any], artifact: ArtifactResolver) -> dict[str, Any]:
        """Pure validation/normalization only. MUST NOT perform an external effect."""
        ...
    def invoke(self, prepared: dict[str, Any], call_id: str) -> ToolResult:
        """One bounded attempt, after the broker commits DISPATCHING."""
        ...
