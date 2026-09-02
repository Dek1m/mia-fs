"""Метрики fs (ADR-002 §11). Лейблы без кардинальности: operation/outcome/kind."""
from __future__ import annotations

from prometheus_client import REGISTRY, Counter, Gauge, Histogram

__all__ = [
    "fs_operations_total",
    "fs_operation_duration_seconds",
    "fs_security_violations_total",
    "fs_share_operations_total",
    "fs_share_grants_added",
    "fs_nodes_registry_total",
    "fs_nodes_update_failed",
]


def _counter(name: str, documentation: str, labelnames: list[str]) -> Counter:
    existing = REGISTRY._names_to_collectors.get(name)
    if existing is not None:
        return existing  # type: ignore[return-value]
    return Counter(name, documentation, labelnames)


def _gauge(name: str, documentation: str, labelnames: list[str]) -> Gauge:
    existing = REGISTRY._names_to_collectors.get(name)
    if existing is not None:
        return existing  # type: ignore[return-value]
    return Gauge(name, documentation, labelnames)


def _histogram(name: str, documentation: str, labelnames: list[str]) -> Histogram:
    existing = REGISTRY._names_to_collectors.get(name)
    if existing is not None:
        return existing  # type: ignore[return-value]
    return Histogram(
        name,
        documentation,
        labelnames=labelnames,
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    )


fs_operations_total = _counter(
    "fs_operations_total",
    "FS operations by RPC; outcome: ok|error|denied",
    ["operation", "outcome"],
)
fs_operation_duration_seconds = _histogram(
    "fs_operation_duration_seconds",
    "FS operation latency on worker",
    ["operation"],
)
fs_security_violations_total = _counter(
    "fs_security_violations_total",
    "Sandbox/ACL violations; kind: PATH_ESCAPE|SYMLINK_ESCAPE|ACL_DENIED|INVALID_NAME",
    ["kind"],
)
fs_share_operations_total = _counter(
    "fs_share_operations_total",
    "Sharing activity by RPC (share_add/share_remove/share_list/resolve_entities/list_shared)",
    ["operation", "outcome"],
)
fs_share_grants_added = _counter(
    "fs_share_grants_added",
    "share_add idempotency volume; outcome: added|skipped",
    ["outcome"],
)
fs_nodes_registry_total = _gauge(
    "fs_nodes_registry_total",
    "fs.nodes live registry size (migrate/health task)",
    [],
)
fs_nodes_update_failed = _counter(
    "fs_nodes_update_failed",
    "Registry/disk divergence on rename/move/trash/restore",
    ["operation"],
)
