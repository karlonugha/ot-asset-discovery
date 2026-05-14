"""Pydantic models and SQLAlchemy ORM models."""

from app.models.database import (
    Alert as AlertORM,
    AuthAttempt,
    Device as DeviceORM,
    DeviceHistory,
    ScanHistory,
    ScanJob,
    TopologyEdge as TopologyEdgeORM,
    User,
)
from app.models.domain import (
    Alert,
    Device,
    DeviceFingerprint,
    ParseResult,
    ProbeResult,
    ProbeTarget,
    ScanJobConfig,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
)

__all__ = [
    # Pydantic domain models
    "Alert",
    "Device",
    "DeviceFingerprint",
    "ParseResult",
    "ProbeResult",
    "ProbeTarget",
    "ScanJobConfig",
    "TopologyEdge",
    "TopologyGraph",
    "TopologyNode",
    # SQLAlchemy ORM models
    "AlertORM",
    "AuthAttempt",
    "DeviceORM",
    "DeviceHistory",
    "ScanHistory",
    "ScanJob",
    "TopologyEdgeORM",
    "User",
]
