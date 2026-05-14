"""OT protocol parsers for Modbus TCP, EtherNet/IP, S7comm, and DNP3.

Also provides serialization/deserialization for DeviceFingerprint objects.
"""

from app.parsers.serialization import (
    DeserializationError,
    SerializationError,
    deserialize_fingerprint,
    get_schema,
    get_supported_versions,
    serialize_fingerprint,
    SUPPORTED_SCHEMA_VERSIONS,
)

__all__ = [
    "DeserializationError",
    "SerializationError",
    "deserialize_fingerprint",
    "get_schema",
    "get_supported_versions",
    "serialize_fingerprint",
    "SUPPORTED_SCHEMA_VERSIONS",
]
