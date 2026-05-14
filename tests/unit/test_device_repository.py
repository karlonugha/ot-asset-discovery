"""Unit tests for the Device_Inventory data access layer.

Tests device creation, re-detection merge logic, MAC+IP uniqueness,
audit history recording, and protocol/history limits.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5

Uses SQLite with type compilation overrides for PostgreSQL-specific types.
"""

import json
import pytest
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import String, Text, JSON, event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import MACADDR, INET, CIDR, ARRAY, JSONB

from app.db.session import Base
from app.db.device_repository import (
    DeviceRepository,
    DuplicateDeviceError,
    ProtocolLimitExceededError,
    MAX_PROTOCOLS_PER_DEVICE,
    MAX_HISTORY_ENTRIES_PER_DEVICE,
)
from app.models.database import Device, DeviceHistory


# Register SQLite-compatible type compilation for PostgreSQL types
@compiles(MACADDR, "sqlite")
def compile_macaddr_sqlite(type_, compiler, **kw):
    return "VARCHAR(17)"


@compiles(INET, "sqlite")
def compile_inet_sqlite(type_, compiler, **kw):
    return "VARCHAR(45)"


@compiles(CIDR, "sqlite")
def compile_cidr_sqlite(type_, compiler, **kw):
    return "VARCHAR(45)"


@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"


# Use SQLite for unit tests (async with aiosqlite)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def async_engine():
    """Create an async SQLite engine for testing."""
    import sqlite3

    # Register adapter so sqlite3 can handle Python lists by serializing to JSON
    sqlite3.register_adapter(list, lambda val: json.dumps(val))
    sqlite3.register_converter("JSON", lambda val: json.loads(val))

    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False, "detect_types": sqlite3.PARSE_DECLTYPES},
        poolclass=StaticPool,
        json_serializer=json.dumps,
        json_deserializer=json.loads,
    )

    async with engine.begin() as conn:
        await conn.run_sync(_create_sqlite_tables)
    yield engine
    await engine.dispose()


def _create_sqlite_tables(connection):
    """Create tables with SQLite-compatible types using raw DDL."""
    from sqlalchemy import text

    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS devices (
            id VARCHAR(36) PRIMARY KEY,
            mac_address VARCHAR(17) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            vendor VARCHAR(128),
            model VARCHAR(128),
            firmware_version VARCHAR(64),
            device_type VARCHAR(50),
            protocols JSON DEFAULT '[]',
            risk_score INTEGER DEFAULT 0,
            fingerprint JSON,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            UNIQUE(mac_address, ip_address)
        )
    """))
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS device_history (
            id VARCHAR(36) PRIMARY KEY,
            device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            field_name VARCHAR(64) NOT NULL,
            old_value TEXT,
            new_value TEXT,
            changed_at DATETIME NOT NULL
        )
    """))
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_device_history_device_id ON device_history(device_id)"
    ))
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_device_history_changed_at ON device_history(changed_at DESC)"
    ))
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS alerts (
            id VARCHAR(36) PRIMARY KEY,
            alert_type VARCHAR(50) NOT NULL,
            severity VARCHAR(10) NOT NULL,
            device_id VARCHAR(36) REFERENCES devices(id) ON DELETE SET NULL,
            details JSON NOT NULL,
            generated_at DATETIME NOT NULL,
            acknowledged BOOLEAN DEFAULT 0
        )
    """))
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS topology_edges (
            id VARCHAR(36) PRIMARY KEY,
            source_device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dest_device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            protocol VARCHAR(30) NOT NULL,
            packet_count INTEGER DEFAULT 0,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            UNIQUE(source_device_id, dest_device_id, protocol)
        )
    """))


@pytest.fixture
async def session(async_engine):
    """Create an async session for testing."""
    session_factory = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
def repo(session):
    """Create a DeviceRepository instance."""
    return DeviceRepository(session)


class TestDeviceCreation:
    """Tests for device creation with all fields (Requirement 4.1)."""

    async def test_create_device_with_all_fields(self, repo, session):
        """Create a device with all fields populated."""
        now = datetime.now(timezone.utc)
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
            model="S7-1200",
            firmware_version="V4.5.0",
            device_type="PLC",
            protocols=["s7comm", "modbus_tcp"],
            fingerprint={"schema_version": "1.0.0", "protocol": "s7comm"},
            first_seen=now,
            last_seen=now,
        )

        assert device.id is not None
        assert device.mac_address == "00:1A:2B:3C:4D:5E"
        assert device.ip_address == "192.168.1.100"
        assert device.vendor == "Siemens"
        assert device.model == "S7-1200"
        assert device.firmware_version == "V4.5.0"
        assert device.device_type == "PLC"
        assert device.protocols == ["s7comm", "modbus_tcp"]
        assert device.fingerprint == {"schema_version": "1.0.0", "protocol": "s7comm"}
        assert device.first_seen == now
        assert device.last_seen == now

    async def test_create_device_with_null_optional_fields(self, repo, session):
        """Create a device with null optional fields (vendor, model, firmware may be null)."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5F",
            ip_address="192.168.1.101",
        )

        assert device.id is not None
        assert device.mac_address == "00:1A:2B:3C:4D:5F"
        assert device.ip_address == "192.168.1.101"
        assert device.vendor is None
        assert device.model is None
        assert device.firmware_version is None
        assert device.device_type is None
        assert device.protocols == []
        assert device.first_seen is not None
        assert device.last_seen is not None

    async def test_create_device_sets_timestamps_automatically(self, repo, session):
        """Device creation sets first_seen and last_seen to current time if not provided."""
        before = datetime.now(timezone.utc)
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:60",
            ip_address="192.168.1.102",
        )
        after = datetime.now(timezone.utc)

        assert before <= device.first_seen <= after
        assert before <= device.last_seen <= after


class TestMacIpUniqueness:
    """Tests for MAC+IP uniqueness enforcement (Requirements 4.3, 4.4)."""

    async def test_duplicate_mac_ip_raises_error(self, repo, session):
        """Inserting a device with existing MAC+IP raises DuplicateDeviceError."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
        )

        with pytest.raises(DuplicateDeviceError):
            await repo.create_device(
                mac_address="00:1A:2B:3C:4D:5E",
                ip_address="192.168.1.100",
                vendor="Allen-Bradley",
            )

    async def test_same_mac_different_ip_allowed(self, repo, session):
        """Same MAC with different IP is allowed (different device record)."""
        device1 = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
        )
        device2 = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.101",
        )

        assert device1.id != device2.id

    async def test_same_ip_different_mac_allowed(self, repo, session):
        """Same IP with different MAC is allowed (different device record)."""
        device1 = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
        )
        device2 = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5F",
            ip_address="192.168.1.100",
        )

        assert device1.id != device2.id

    async def test_get_device_by_mac_ip_returns_existing(self, repo, session):
        """get_device_by_mac_ip returns the device when it exists."""
        created = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
        )

        found = await repo.get_device_by_mac_ip("00:1A:2B:3C:4D:5E", "192.168.1.100")
        assert found is not None
        assert found.id == created.id

    async def test_get_device_by_mac_ip_returns_none_for_missing(self, repo, session):
        """get_device_by_mac_ip returns None when no device matches."""
        found = await repo.get_device_by_mac_ip("00:1A:2B:3C:4D:5E", "192.168.1.100")
        assert found is None


class TestReDetectionMerge:
    """Tests for re-detection merge logic (Requirement 4.2)."""

    async def test_redetection_updates_last_seen(self, repo, session):
        """Re-detection updates the last_seen timestamp."""
        original_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
            last_seen=original_time,
        )

        new_time = datetime(2024, 1, 2, tzinfo=timezone.utc)
        device, is_new = await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            last_seen=new_time,
        )

        assert is_new is False
        assert device.last_seen == new_time

    async def test_redetection_fills_null_fields(self, repo, session):
        """Re-detection fills in fields that were previously null."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor=None,
            model=None,
            firmware_version=None,
        )

        device, is_new = await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
            model="S7-1200",
            firmware_version="V4.5.0",
        )

        assert is_new is False
        assert device.vendor == "Siemens"
        assert device.model == "S7-1200"
        assert device.firmware_version == "V4.5.0"

    async def test_redetection_never_overwrites_non_null(self, repo, session):
        """Re-detection never overwrites fields that already have values."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
            model="S7-1200",
            firmware_version="V4.5.0",
        )

        device, is_new = await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Allen-Bradley",
            model="CompactLogix",
            firmware_version="V32.0",
        )

        assert is_new is False
        # Original values preserved
        assert device.vendor == "Siemens"
        assert device.model == "S7-1200"
        assert device.firmware_version == "V4.5.0"

    async def test_redetection_partial_fill(self, repo, session):
        """Re-detection fills only null fields, preserves non-null ones."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
            model=None,
            firmware_version=None,
        )

        device, is_new = await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Allen-Bradley",  # Should NOT overwrite
            model="S7-1200",  # Should fill
            firmware_version="V4.5.0",  # Should fill
        )

        assert is_new is False
        assert device.vendor == "Siemens"  # Preserved
        assert device.model == "S7-1200"  # Filled
        assert device.firmware_version == "V4.5.0"  # Filled

    async def test_upsert_creates_new_device_if_not_exists(self, repo, session):
        """upsert_device creates a new device if MAC+IP doesn't exist."""
        device, is_new = await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
        )

        assert is_new is True
        assert device.vendor == "Siemens"

    async def test_redetection_merges_new_protocols(self, repo, session):
        """Re-detection adds new protocols to the existing list."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=["modbus_tcp"],
        )

        device, is_new = await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=["modbus_tcp", "s7comm"],
        )

        assert is_new is False
        assert "modbus_tcp" in device.protocols
        assert "s7comm" in device.protocols
        assert len(device.protocols) == 2

    async def test_redetection_does_not_duplicate_protocols(self, repo, session):
        """Re-detection doesn't add protocols that already exist in the list."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=["modbus_tcp", "s7comm"],
        )

        device, is_new = await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=["modbus_tcp"],
        )

        assert is_new is False
        assert device.protocols == ["modbus_tcp", "s7comm"]


class TestProtocolLimit:
    """Tests for maximum 20 protocols per device (Requirement 4.1)."""

    async def test_create_device_with_max_protocols(self, repo, session):
        """Creating a device with exactly 20 protocols succeeds."""
        protocols = [f"proto_{i}" for i in range(20)]
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=protocols,
        )

        assert len(device.protocols) == 20

    async def test_create_device_exceeding_protocol_limit_raises(self, repo, session):
        """Creating a device with more than 20 protocols raises error."""
        protocols = [f"proto_{i}" for i in range(21)]

        with pytest.raises(ProtocolLimitExceededError):
            await repo.create_device(
                mac_address="00:1A:2B:3C:4D:5E",
                ip_address="192.168.1.100",
                protocols=protocols,
            )

    async def test_merge_exceeding_protocol_limit_raises(self, repo, session):
        """Merging protocols that would exceed 20 raises error."""
        protocols = [f"proto_{i}" for i in range(19)]
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=protocols,
        )

        # Adding 2 new protocols would make 21 total
        with pytest.raises(ProtocolLimitExceededError):
            await repo.upsert_device(
                mac_address="00:1A:2B:3C:4D:5E",
                ip_address="192.168.1.100",
                protocols=[f"proto_{i}" for i in range(19, 21)],
            )


class TestAuditHistory:
    """Tests for audit history recording (Requirement 4.5)."""

    async def test_filling_null_field_records_history(self, repo, session):
        """Filling a null field during re-detection records a history entry."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor=None,
        )

        await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            vendor="Siemens",
        )

        device = await repo.get_device_by_mac_ip("00:1A:2B:3C:4D:5E", "192.168.1.100")
        history = await repo.get_device_history(device.id)

        assert len(history) == 1
        assert history[0].field_name == "vendor"
        assert history[0].old_value is None
        assert history[0].new_value == "Siemens"

    async def test_explicit_attribute_change_records_history(self, repo, session):
        """Explicit attribute update records old and new values in history."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            firmware_version="V4.5.0",
        )

        await repo.update_device_attribute(
            device.id, "firmware_version", "V4.6.0"
        )

        history = await repo.get_device_history(device.id)
        assert len(history) == 1
        assert history[0].field_name == "firmware_version"
        assert history[0].old_value == "V4.5.0"
        assert history[0].new_value == "V4.6.0"

    async def test_protocol_merge_records_history(self, repo, session):
        """Adding new protocols during re-detection records history."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=["modbus_tcp"],
        )

        await repo.upsert_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=["s7comm"],
        )

        device = await repo.get_device_by_mac_ip("00:1A:2B:3C:4D:5E", "192.168.1.100")
        history = await repo.get_device_history(device.id)

        assert len(history) == 1
        assert history[0].field_name == "protocols"
        assert history[0].old_value == "modbus_tcp"
        assert "modbus_tcp" in history[0].new_value
        assert "s7comm" in history[0].new_value

    async def test_history_entries_ordered_by_timestamp_desc(self, repo, session):
        """History entries are returned in descending timestamp order."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            firmware_version="V1.0",
        )

        await repo.update_device_attribute(device.id, "firmware_version", "V2.0")
        await repo.update_device_attribute(device.id, "firmware_version", "V3.0")

        history = await repo.get_device_history(device.id)
        assert len(history) == 2
        # Most recent first
        assert history[0].new_value == "V3.0"
        assert history[1].new_value == "V2.0"

    async def test_history_count(self, repo, session):
        """get_device_history_count returns correct count."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            firmware_version="V1.0",
        )

        await repo.update_device_attribute(device.id, "firmware_version", "V2.0")
        await repo.update_device_attribute(device.id, "firmware_version", "V3.0")

        count = await repo.get_device_history_count(device.id)
        assert count == 2


class TestHistoryLimit:
    """Tests for maximum 1000 history entries per device (Requirement 4.5)."""

    async def test_history_entries_within_limit_preserved(self, repo, session):
        """History entries within the 1000 limit are all preserved."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            firmware_version="V0",
        )

        # Create 11 entries (well under limit)
        for i in range(1, 12):
            await repo.update_device_attribute(
                device.id, "firmware_version", f"V{i}"
            )

        count = await repo.get_device_history_count(device.id)
        assert count == 11


class TestUpdateDeviceAttribute:
    """Tests for explicit device attribute updates."""

    async def test_update_firmware_version(self, repo, session):
        """Updating firmware_version changes the value and records history."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            firmware_version="V4.5.0",
        )

        updated = await repo.update_device_attribute(
            device.id, "firmware_version", "V4.6.0"
        )

        assert updated.firmware_version == "V4.6.0"

    async def test_update_invalid_field_raises(self, repo, session):
        """Updating an invalid field name raises ValueError."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
        )

        with pytest.raises(ValueError, match="not a tracked attribute"):
            await repo.update_device_attribute(device.id, "invalid_field", "value")

    async def test_update_nonexistent_device_raises(self, repo, session):
        """Updating a non-existent device raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            await repo.update_device_attribute(uuid4(), "firmware_version", "V1.0")

    async def test_update_protocols_field(self, repo, session):
        """Updating protocols field parses comma-separated string."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
            protocols=["modbus_tcp"],
        )

        updated = await repo.update_device_attribute(
            device.id, "protocols", "modbus_tcp,s7comm,ethernetip"
        )

        assert updated.protocols == ["modbus_tcp", "s7comm", "ethernetip"]

    async def test_update_protocols_exceeding_limit_raises(self, repo, session):
        """Updating protocols to exceed 20 raises ProtocolLimitExceededError."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E",
            ip_address="192.168.1.100",
        )

        protocols_str = ",".join(f"proto_{i}" for i in range(21))
        with pytest.raises(ProtocolLimitExceededError):
            await repo.update_device_attribute(device.id, "protocols", protocols_str)


class TestListAndDelete:
    """Tests for listing and deleting devices."""

    async def test_list_devices_returns_all(self, repo, session):
        """list_devices returns all devices when no filters applied."""
        await repo.create_device(mac_address="00:1A:2B:3C:4D:01", ip_address="192.168.1.1")
        await repo.create_device(mac_address="00:1A:2B:3C:4D:02", ip_address="192.168.1.2")

        devices = await repo.list_devices()
        assert len(devices) == 2

    async def test_list_devices_with_vendor_filter(self, repo, session):
        """list_devices filters by vendor."""
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:01", ip_address="192.168.1.1", vendor="Siemens"
        )
        await repo.create_device(
            mac_address="00:1A:2B:3C:4D:02", ip_address="192.168.1.2", vendor="Allen-Bradley"
        )

        devices = await repo.list_devices(vendor="Siemens")
        assert len(devices) == 1
        assert devices[0].vendor == "Siemens"

    async def test_delete_device(self, repo, session):
        """delete_device removes the device."""
        device = await repo.create_device(
            mac_address="00:1A:2B:3C:4D:5E", ip_address="192.168.1.100"
        )

        result = await repo.delete_device(device.id)
        assert result is True

        found = await repo.get_device_by_id(device.id)
        assert found is None

    async def test_delete_nonexistent_device_returns_false(self, repo, session):
        """delete_device returns False for non-existent device."""
        result = await repo.delete_device(uuid4())
        assert result is False
