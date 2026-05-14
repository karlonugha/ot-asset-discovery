"""Unit tests for device CRUD endpoints.

Tests the HTTP-level behavior of device endpoints:
- GET /api/devices with filtering and pagination
- GET /api/devices/{device_id} with historical changes
- POST /api/devices (admin only)
- PUT /api/devices/{device_id} (admin only)
- DELETE /api/devices/{device_id} (admin only)
- RBAC enforcement (viewer for reads, admin for writes)

Requirements: 4.6, 4.7

Uses SQLite with type compilation overrides for PostgreSQL-specific types.
"""

import json
import pytest
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import MACADDR, INET, CIDR, JSONB

from app.api.auth import create_access_token
from app.api.devices_router import devices_router
from app.db.session import Base, get_session
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


def _create_sqlite_tables(connection):
    """Create tables with SQLite-compatible types using raw DDL."""
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
def test_app():
    """Create a test FastAPI app with the devices router."""
    import sqlite3
    sqlite3.register_adapter(list, lambda val: json.dumps(val))
    sqlite3.register_converter("JSON", lambda val: json.loads(val))

    app = FastAPI()
    app.include_router(devices_router)

    # Create engine and session factory
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False, "detect_types": sqlite3.PARSE_DECLTYPES},
        poolclass=StaticPool,
        json_serializer=json.dumps,
        json_deserializer=json.loads,
    )

    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    # Override the get_session dependency
    async def override_get_session():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    # Store engine on app for setup
    app._test_engine = engine
    app._test_session_factory = session_factory

    return app


@pytest.fixture
def setup_db(test_app):
    """Set up the database tables synchronously before tests."""
    import asyncio

    async def _setup():
        async with test_app._test_engine.begin() as conn:
            await conn.run_sync(_create_sqlite_tables)

    asyncio.run(_setup())


@pytest.fixture
def client(test_app, setup_db):
    """Create a test client."""
    return TestClient(test_app)


@pytest.fixture
def admin_token():
    """Create an admin JWT token."""
    return create_access_token("admin_user", "admin")


@pytest.fixture
def viewer_token():
    """Create a viewer JWT token."""
    return create_access_token("viewer_user", "viewer")


@pytest.fixture
def admin_headers(admin_token):
    """Authorization headers for admin user."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    """Authorization headers for viewer user."""
    return {"Authorization": f"Bearer {viewer_token}"}


class TestListDevices:
    """Tests for GET /api/devices endpoint."""

    def test_list_devices_requires_auth(self, client):
        """Listing devices without auth returns 401."""
        response = client.get("/api/devices")
        assert response.status_code == 401

    def test_list_devices_empty(self, client, viewer_headers):
        """Listing devices when none exist returns empty list."""
        response = client.get("/api/devices", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["limit"] == 50
        assert data["offset"] == 0

    def test_list_devices_returns_created_devices(self, client, admin_headers, viewer_headers):
        """Listing devices returns previously created devices."""
        # Create a device
        client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "vendor": "Siemens",
                "model": "S7-1200",
            },
            headers=admin_headers,
        )

        response = client.get("/api/devices", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["vendor"] == "Siemens"

    def test_list_devices_default_pagination(self, client, viewer_headers):
        """Default pagination is 50 records per page."""
        response = client.get("/api/devices", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 50

    def test_list_devices_custom_pagination(self, client, viewer_headers):
        """Custom pagination parameters are respected."""
        response = client.get(
            "/api/devices?limit=10&offset=5", headers=viewer_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 5

    def test_list_devices_max_limit_500(self, client, viewer_headers):
        """Limit is capped at 500."""
        response = client.get("/api/devices?limit=1000", headers=viewer_headers)
        assert response.status_code == 422  # FastAPI validation error for le=500

    def test_list_devices_filter_by_vendor(self, client, admin_headers, viewer_headers):
        """Filtering by vendor returns only matching devices."""
        client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:01", "ip_address": "192.168.1.1", "vendor": "Siemens"},
            headers=admin_headers,
        )
        client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:02", "ip_address": "192.168.1.2", "vendor": "Allen-Bradley"},
            headers=admin_headers,
        )

        response = client.get("/api/devices?vendor=Siemens", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["vendor"] == "Siemens"

    def test_list_devices_filter_by_model(self, client, admin_headers, viewer_headers):
        """Filtering by model returns only matching devices."""
        client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:01", "ip_address": "192.168.1.1", "model": "S7-1200"},
            headers=admin_headers,
        )
        client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:02", "ip_address": "192.168.1.2", "model": "CompactLogix"},
            headers=admin_headers,
        )

        response = client.get("/api/devices?model=S7", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["model"] == "S7-1200"

    def test_list_devices_filter_by_risk_score_range(self, client, admin_headers, viewer_headers):
        """Filtering by risk score range returns only matching devices."""
        # Create devices with different risk scores
        resp1 = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:01", "ip_address": "192.168.1.1"},
            headers=admin_headers,
        )
        resp2 = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:02", "ip_address": "192.168.1.2"},
            headers=admin_headers,
        )

        # Update risk scores
        device1_id = resp1.json()["id"]
        device2_id = resp2.json()["id"]
        client.put(
            f"/api/devices/{device1_id}",
            json={"risk_score": 80},
            headers=admin_headers,
        )
        client.put(
            f"/api/devices/{device2_id}",
            json={"risk_score": 20},
            headers=admin_headers,
        )

        response = client.get(
            "/api/devices?risk_score_min=50&risk_score_max=100",
            headers=viewer_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["risk_score"] == 80

    @pytest.mark.skipif(True, reason="Protocol filter uses PostgreSQL ANY() which is not available in SQLite")
    def test_list_devices_filter_by_protocol(self, client, admin_headers, viewer_headers):
        """Filtering by protocol returns only devices with that protocol.

        Note: This test requires PostgreSQL because the protocol filter uses
        the ANY() array operator which is not supported by SQLite.
        """
        client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:01",
                "ip_address": "192.168.1.1",
                "protocols": ["modbus_tcp", "s7comm"],
            },
            headers=admin_headers,
        )
        client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:02",
                "ip_address": "192.168.1.2",
                "protocols": ["ethernetip"],
            },
            headers=admin_headers,
        )

        response = client.get("/api/devices?protocol=modbus_tcp", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert "modbus_tcp" in data["items"][0]["protocols"]

    def test_list_devices_filter_by_subnet_invalid(self, client, viewer_headers):
        """Filtering by invalid subnet returns 400."""
        response = client.get("/api/devices?subnet=not-a-cidr", headers=viewer_headers)
        assert response.status_code == 400
        assert "Invalid subnet" in response.json()["detail"]

    def test_list_devices_combined_filters(self, client, admin_headers, viewer_headers):
        """Multiple filters are applied together (AND logic)."""
        client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:01",
                "ip_address": "192.168.1.1",
                "vendor": "Siemens",
                "model": "S7-1200",
                "protocols": ["s7comm"],
            },
            headers=admin_headers,
        )
        client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:02",
                "ip_address": "192.168.1.2",
                "vendor": "Siemens",
                "model": "S7-300",
                "protocols": ["modbus_tcp"],
            },
            headers=admin_headers,
        )
        client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:03",
                "ip_address": "192.168.1.3",
                "vendor": "Allen-Bradley",
                "model": "CompactLogix",
                "protocols": ["ethernetip"],
            },
            headers=admin_headers,
        )

        # Filter by vendor AND model
        response = client.get(
            "/api/devices?vendor=Siemens&model=S7-1200", headers=viewer_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["model"] == "S7-1200"

    def test_list_devices_pagination_offset(self, client, admin_headers, viewer_headers):
        """Pagination offset correctly skips records."""
        # Create 3 devices
        for i in range(3):
            client.post(
                "/api/devices",
                json={
                    "mac_address": f"00:1A:2B:3C:4D:{i:02X}",
                    "ip_address": f"192.168.1.{i + 1}",
                    "vendor": f"Vendor{i}",
                },
                headers=admin_headers,
            )

        # Get with offset
        response = client.get("/api/devices?limit=2&offset=1", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert len(data["items"]) == 2
        assert data["offset"] == 1

    def test_list_devices_viewer_can_access(self, client, viewer_headers):
        """Viewer role can list devices (read access)."""
        response = client.get("/api/devices", headers=viewer_headers)
        assert response.status_code == 200


class TestGetDevice:
    """Tests for GET /api/devices/{device_id} endpoint."""

    def test_get_device_requires_auth(self, client):
        """Getting a device without auth returns 401."""
        response = client.get(f"/api/devices/{uuid4()}")
        assert response.status_code == 401

    def test_get_device_not_found(self, client, viewer_headers):
        """Getting a non-existent device returns 404."""
        response = client.get(f"/api/devices/{uuid4()}", headers=viewer_headers)
        assert response.status_code == 404

    def test_get_device_returns_detail(self, client, admin_headers, viewer_headers):
        """Getting an existing device returns full detail."""
        # Create a device
        create_resp = client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "vendor": "Siemens",
                "model": "S7-1200",
                "firmware_version": "V4.5.0",
                "device_type": "PLC",
                "protocols": ["s7comm", "modbus_tcp"],
            },
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        response = client.get(f"/api/devices/{device_id}", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == device_id
        assert data["vendor"] == "Siemens"
        assert data["model"] == "S7-1200"
        assert data["firmware_version"] == "V4.5.0"
        assert data["device_type"] == "PLC"
        assert data["protocols"] == ["s7comm", "modbus_tcp"]
        assert "history" in data
        assert "history_total" in data

    def test_get_device_includes_history(self, client, admin_headers, viewer_headers):
        """Getting a device includes its attribute change history."""
        # Create and update a device
        create_resp = client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "firmware_version": "V4.5.0",
            },
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        # Update firmware to create history
        client.put(
            f"/api/devices/{device_id}",
            json={"firmware_version": "V4.6.0"},
            headers=admin_headers,
        )

        response = client.get(f"/api/devices/{device_id}", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["history_total"] >= 1
        assert len(data["history"]) >= 1
        # Check history entry
        history_entry = data["history"][0]
        assert history_entry["field_name"] == "firmware_version"
        assert history_entry["old_value"] == "V4.5.0"
        assert history_entry["new_value"] == "V4.6.0"

    def test_get_device_history_pagination(self, client, admin_headers, viewer_headers):
        """Device history is paginated with default 100 entries."""
        create_resp = client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "firmware_version": "V1.0",
            },
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        # Create multiple history entries
        for i in range(2, 6):
            client.put(
                f"/api/devices/{device_id}",
                json={"firmware_version": f"V{i}.0"},
                headers=admin_headers,
            )

        # Get with custom history pagination
        response = client.get(
            f"/api/devices/{device_id}?history_limit=2&history_offset=0",
            headers=viewer_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["history"]) == 2
        assert data["history_total"] == 4  # 4 firmware changes


class TestCreateDevice:
    """Tests for POST /api/devices endpoint."""

    def test_create_device_requires_auth(self, client):
        """Creating a device without auth returns 401."""
        response = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
        )
        assert response.status_code == 401

    def test_create_device_requires_admin(self, client, viewer_headers):
        """Creating a device with viewer role returns 403."""
        response = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=viewer_headers,
        )
        assert response.status_code == 403

    def test_create_device_success(self, client, admin_headers):
        """Creating a device with admin role succeeds."""
        response = client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "vendor": "Siemens",
                "model": "S7-1200",
                "firmware_version": "V4.5.0",
                "device_type": "PLC",
                "protocols": ["s7comm"],
            },
            headers=admin_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["mac_address"] == "00:1A:2B:3C:4D:5E"
        assert data["ip_address"] == "192.168.1.100"
        assert data["vendor"] == "Siemens"
        assert data["model"] == "S7-1200"
        assert data["id"] is not None

    def test_create_device_duplicate_returns_409(self, client, admin_headers):
        """Creating a device with existing MAC+IP returns 409."""
        client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=admin_headers,
        )

        response = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=admin_headers,
        )
        assert response.status_code == 409

    def test_create_device_too_many_protocols_returns_400(self, client, admin_headers):
        """Creating a device with >20 protocols returns 400."""
        protocols = [f"proto_{i}" for i in range(21)]
        response = client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "protocols": protocols,
            },
            headers=admin_headers,
        )
        assert response.status_code == 400

    def test_create_device_minimal_fields(self, client, admin_headers):
        """Creating a device with only required fields succeeds."""
        response = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=admin_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["vendor"] is None
        assert data["model"] is None
        assert data["firmware_version"] is None
        assert data["protocols"] == []


class TestUpdateDevice:
    """Tests for PUT /api/devices/{device_id} endpoint."""

    def test_update_device_requires_auth(self, client):
        """Updating a device without auth returns 401."""
        response = client.put(
            f"/api/devices/{uuid4()}",
            json={"vendor": "Siemens"},
        )
        assert response.status_code == 401

    def test_update_device_requires_admin(self, client, admin_headers, viewer_headers):
        """Updating a device with viewer role returns 403."""
        # Create a device first
        create_resp = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        response = client.put(
            f"/api/devices/{device_id}",
            json={"vendor": "Siemens"},
            headers=viewer_headers,
        )
        assert response.status_code == 403

    def test_update_device_not_found(self, client, admin_headers):
        """Updating a non-existent device returns 404."""
        response = client.put(
            f"/api/devices/{uuid4()}",
            json={"vendor": "Siemens"},
            headers=admin_headers,
        )
        assert response.status_code == 404

    def test_update_device_success(self, client, admin_headers):
        """Updating a device with admin role succeeds."""
        create_resp = client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "vendor": "Unknown",
            },
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        response = client.put(
            f"/api/devices/{device_id}",
            json={"vendor": "Siemens", "model": "S7-1200"},
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["vendor"] == "Siemens"
        assert data["model"] == "S7-1200"

    def test_update_device_risk_score(self, client, admin_headers):
        """Updating risk score succeeds."""
        create_resp = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        response = client.put(
            f"/api/devices/{device_id}",
            json={"risk_score": 75},
            headers=admin_headers,
        )
        assert response.status_code == 200
        assert response.json()["risk_score"] == 75

    def test_update_device_protocols(self, client, admin_headers):
        """Updating protocols succeeds."""
        create_resp = client.post(
            "/api/devices",
            json={
                "mac_address": "00:1A:2B:3C:4D:5E",
                "ip_address": "192.168.1.100",
                "protocols": ["modbus_tcp"],
            },
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        response = client.put(
            f"/api/devices/{device_id}",
            json={"protocols": ["modbus_tcp", "s7comm", "ethernetip"]},
            headers=admin_headers,
        )
        assert response.status_code == 200
        assert set(response.json()["protocols"]) == {"modbus_tcp", "s7comm", "ethernetip"}


class TestDeleteDevice:
    """Tests for DELETE /api/devices/{device_id} endpoint."""

    def test_delete_device_requires_auth(self, client):
        """Deleting a device without auth returns 401."""
        response = client.delete(f"/api/devices/{uuid4()}")
        assert response.status_code == 401

    def test_delete_device_requires_admin(self, client, admin_headers, viewer_headers):
        """Deleting a device with viewer role returns 403."""
        create_resp = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        response = client.delete(
            f"/api/devices/{device_id}", headers=viewer_headers
        )
        assert response.status_code == 403

    def test_delete_device_not_found(self, client, admin_headers):
        """Deleting a non-existent device returns 404."""
        response = client.delete(
            f"/api/devices/{uuid4()}", headers=admin_headers
        )
        assert response.status_code == 404

    def test_delete_device_success(self, client, admin_headers, viewer_headers):
        """Deleting a device with admin role succeeds."""
        create_resp = client.post(
            "/api/devices",
            json={"mac_address": "00:1A:2B:3C:4D:5E", "ip_address": "192.168.1.100"},
            headers=admin_headers,
        )
        device_id = create_resp.json()["id"]

        response = client.delete(
            f"/api/devices/{device_id}", headers=admin_headers
        )
        assert response.status_code == 204

        # Verify device is gone
        get_resp = client.get(
            f"/api/devices/{device_id}", headers=viewer_headers
        )
        assert get_resp.status_code == 404
