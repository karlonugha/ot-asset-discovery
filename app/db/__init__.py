"""Database configuration and session management."""

from app.db.session import Base, engine, async_session_factory, get_session


def get_device_repository():
    """Lazy import to avoid circular dependency."""
    from app.db.device_repository import DeviceRepository
    return DeviceRepository


def get_device_repository_errors():
    """Lazy import to avoid circular dependency."""
    from app.db.device_repository import (
        DeviceInventoryError,
        DuplicateDeviceError,
        ProtocolLimitExceededError,
        MAX_PROTOCOLS_PER_DEVICE,
        MAX_HISTORY_ENTRIES_PER_DEVICE,
    )
    return {
        "DeviceInventoryError": DeviceInventoryError,
        "DuplicateDeviceError": DuplicateDeviceError,
        "ProtocolLimitExceededError": ProtocolLimitExceededError,
        "MAX_PROTOCOLS_PER_DEVICE": MAX_PROTOCOLS_PER_DEVICE,
        "MAX_HISTORY_ENTRIES_PER_DEVICE": MAX_HISTORY_ENTRIES_PER_DEVICE,
    }


__all__ = [
    "Base",
    "engine",
    "async_session_factory",
    "get_session",
    "get_device_repository",
    "get_device_repository_errors",
]
