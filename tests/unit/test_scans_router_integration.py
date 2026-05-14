"""HTTP-level integration tests for scan management API endpoints.

Tests the full request/response cycle through FastAPI TestClient:
- CRUD endpoints for Scan_Job schedules at /api/scans
- GET historical scan results with pagination (default 20, max 100) and date range filtering
- POST endpoint for manual scan trigger (execution within 5 seconds)
- Cron schedule validation (minimum interval of 5 minutes)
- RBAC enforcement (admin for writes, viewer for reads)
- 404 handling for non-existent resources

Requirements: 11.1, 11.3, 11.4, 11.5

Uses SQLite with type compilation overrides for PostgreSQL-specific types.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import MACADDR, INET, CIDR, JSONB
from sqlalchemy.pool import StaticPool

from app.api.auth import create_access_token
from app.api.router_scans import scans_router
from app.db.session import Base, get_session


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


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


def _create_sqlite_tables(connection):
    """Create scan-related tables with SQLite-compatible DDL."""
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
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(128) NOT NULL,
            schedule VARCHAR(64),
            target_subnet VARCHAR(45),
            active_probing_enabled BOOLEAN DEFAULT 0,
            status VARCHAR(20) NOT NULL DEFAULT 'scheduled',
            started_at DATETIME,
            completed_at DATETIME,
            devices_discovered INTEGER DEFAULT 0,
            new_devices INTEGER DEFAULT 0,
            alerts_generated INTEGER DEFAULT 0,
            failure_reason TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """))
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id VARCHAR(36) PRIMARY KEY,
            scan_job_id VARCHAR(36) NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            status VARCHAR(20) NOT NULL,
            started_at DATETIME NOT NULL,
            completed_at DATETIME,
            devices_discovered INTEGER DEFAULT 0,
            new_devices INTEGER DEFAULT 0,
            alerts_generated INTEGER DEFAULT 0,
            failure_reason TEXT
        )
    """))
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_scan_history_job_id ON scan_history(scan_job_id)"
    ))
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_scan_history_started_at ON scan_history(started_at DESC)"
    ))
    # Required for foreign key references in other tables
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


@pytest.fixture
def test_app():
    """Create a test FastAPI app with the scans router."""
    sqlite3.register_adapter(list, lambda val: json.dumps(val))
    sqlite3.register_converter("JSON", lambda val: json.loads(val))

    app = FastAPI()
    app.include_router(scans_router)

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

    async def override_get_session():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    app._test_engine = engine
    app._test_session_factory = session_factory

    return app


@pytest.fixture
def setup_db(test_app):
    """Set up the database tables before tests."""
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


# --- CRUD Tests ---


class TestCreateScanJob:
    """Tests for POST /api/scans endpoint."""

    def test_create_requires_auth(self, client):
        """Creating a scan job without auth returns 401."""
        response = client.post("/api/scans", json={"name": "Test Scan"})
        assert response.status_code == 401

    def test_create_requires_admin(self, client, viewer_headers):
        """Creating a scan job with viewer role returns 403."""
        response = client.post(
            "/api/scans", json={"name": "Test Scan"}, headers=viewer_headers
        )
        assert response.status_code == 403

    def test_create_minimal(self, client, admin_headers):
        """Creating a scan job with only name succeeds."""
        response = client.post(
            "/api/scans", json={"name": "Quick Scan"}, headers=admin_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Quick Scan"
        assert data["schedule"] is None
        assert data["target_subnet"] is None
        assert data["active_probing_enabled"] is False
        assert data["status"] == "scheduled"
        assert data["id"] is not None

    def test_create_full(self, client, admin_headers):
        """Creating a scan job with all fields succeeds."""
        response = client.post(
            "/api/scans",
            json={
                "name": "Daily OT Scan",
                "schedule": "0 0 * * *",
                "target_subnet": "192.168.1.0/24",
                "active_probing_enabled": True,
            },
            headers=admin_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Daily OT Scan"
        assert data["schedule"] == "0 0 * * *"
        assert data["target_subnet"] == "192.168.1.0/24"
        assert data["active_probing_enabled"] is True

    def test_create_rejects_invalid_cron(self, client, admin_headers):
        """Creating with invalid cron expression returns 422."""
        response = client.post(
            "/api/scans",
            json={"name": "Bad Scan", "schedule": "not-a-cron"},
            headers=admin_headers,
        )
        assert response.status_code == 422

    def test_create_rejects_cron_under_5_minutes(self, client, admin_headers):
        """Creating with cron interval < 5 minutes returns 422."""
        response = client.post(
            "/api/scans",
            json={"name": "Too Frequent", "schedule": "* * * * *"},
            headers=admin_headers,
        )
        assert response.status_code == 422
        assert "at least 5 minutes" in response.json()["detail"]

    def test_create_accepts_exactly_5_minutes(self, client, admin_headers):
        """Creating with exactly 5-minute interval succeeds."""
        response = client.post(
            "/api/scans",
            json={"name": "Five Min Scan", "schedule": "*/5 * * * *"},
            headers=admin_headers,
        )
        assert response.status_code == 201

    def test_create_rejects_empty_name(self, client, admin_headers):
        """Creating with empty name returns 422."""
        response = client.post(
            "/api/scans", json={"name": ""}, headers=admin_headers
        )
        assert response.status_code == 422

    def test_create_rejects_name_too_long(self, client, admin_headers):
        """Creating with name > 128 chars returns 422."""
        response = client.post(
            "/api/scans", json={"name": "x" * 129}, headers=admin_headers
        )
        assert response.status_code == 422


class TestListScanJobs:
    """Tests for GET /api/scans endpoint."""

    def test_list_requires_auth(self, client):
        """Listing scan jobs without auth returns 401."""
        response = client.get("/api/scans")
        assert response.status_code == 401

    def test_list_empty(self, client, viewer_headers):
        """Listing when no scan jobs exist returns empty list."""
        response = client.get("/api/scans", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["page_size"] == 20

    def test_list_returns_created_jobs(self, client, admin_headers, viewer_headers):
        """Listing returns previously created scan jobs."""
        client.post(
            "/api/scans", json={"name": "Scan A"}, headers=admin_headers
        )
        client.post(
            "/api/scans", json={"name": "Scan B"}, headers=admin_headers
        )

        response = client.get("/api/scans", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_list_default_pagination(self, client, viewer_headers):
        """Default page size is 20."""
        response = client.get("/api/scans", headers=viewer_headers)
        assert response.status_code == 200
        assert response.json()["page_size"] == 20

    def test_list_custom_pagination(self, client, admin_headers, viewer_headers):
        """Custom page size is respected."""
        for i in range(5):
            client.post(
                "/api/scans", json={"name": f"Scan {i}"}, headers=admin_headers
            )

        response = client.get("/api/scans?page_size=2&page=2", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["page_size"] == 2
        assert data["page"] == 2
        assert len(data["items"]) == 2
        assert data["total"] == 5
        assert data["total_pages"] == 3

    def test_list_max_page_size_100(self, client, viewer_headers):
        """Page size > 100 returns 422."""
        response = client.get("/api/scans?page_size=101", headers=viewer_headers)
        assert response.status_code == 422

    def test_list_viewer_can_access(self, client, viewer_headers):
        """Viewer role can list scan jobs (read access)."""
        response = client.get("/api/scans", headers=viewer_headers)
        assert response.status_code == 200


class TestGetScanJob:
    """Tests for GET /api/scans/{scan_id} endpoint."""

    def test_get_requires_auth(self, client):
        """Getting a scan job without auth returns 401."""
        response = client.get(f"/api/scans/{uuid4()}")
        assert response.status_code == 401

    def test_get_not_found(self, client, viewer_headers):
        """Getting a non-existent scan job returns 404."""
        response = client.get(f"/api/scans/{uuid4()}", headers=viewer_headers)
        assert response.status_code == 404

    def test_get_returns_detail(self, client, admin_headers, viewer_headers):
        """Getting an existing scan job returns full detail."""
        create_resp = client.post(
            "/api/scans",
            json={
                "name": "Detail Scan",
                "schedule": "*/10 * * * *",
                "target_subnet": "10.0.0.0/8",
                "active_probing_enabled": True,
            },
            headers=admin_headers,
        )
        scan_id = create_resp.json()["id"]

        response = client.get(f"/api/scans/{scan_id}", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scan_id
        assert data["name"] == "Detail Scan"
        assert data["schedule"] == "*/10 * * * *"
        assert data["target_subnet"] == "10.0.0.0/8"
        assert data["active_probing_enabled"] is True
        assert data["status"] == "scheduled"


class TestUpdateScanJob:
    """Tests for PUT /api/scans/{scan_id} endpoint."""

    def test_update_requires_auth(self, client):
        """Updating a scan job without auth returns 401."""
        response = client.put(
            f"/api/scans/{uuid4()}", json={"name": "Updated"}
        )
        assert response.status_code == 401

    def test_update_requires_admin(self, client, admin_headers, viewer_headers):
        """Updating a scan job with viewer role returns 403."""
        create_resp = client.post(
            "/api/scans", json={"name": "Original"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.put(
            f"/api/scans/{scan_id}",
            json={"name": "Updated"},
            headers=viewer_headers,
        )
        assert response.status_code == 403

    def test_update_not_found(self, client, admin_headers):
        """Updating a non-existent scan job returns 404."""
        response = client.put(
            f"/api/scans/{uuid4()}", json={"name": "Updated"}, headers=admin_headers
        )
        assert response.status_code == 404

    def test_update_name(self, client, admin_headers):
        """Updating the name succeeds."""
        create_resp = client.post(
            "/api/scans", json={"name": "Original"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.put(
            f"/api/scans/{scan_id}",
            json={"name": "Updated Name"},
            headers=admin_headers,
        )
        assert response.status_code == 200
        assert response.json()["name"] == "Updated Name"

    def test_update_schedule(self, client, admin_headers):
        """Updating the schedule validates cron expression."""
        create_resp = client.post(
            "/api/scans",
            json={"name": "Scheduled", "schedule": "*/5 * * * *"},
            headers=admin_headers,
        )
        scan_id = create_resp.json()["id"]

        response = client.put(
            f"/api/scans/{scan_id}",
            json={"schedule": "*/10 * * * *"},
            headers=admin_headers,
        )
        assert response.status_code == 200
        assert response.json()["schedule"] == "*/10 * * * *"

    def test_update_rejects_invalid_schedule(self, client, admin_headers):
        """Updating with invalid cron returns 422."""
        create_resp = client.post(
            "/api/scans", json={"name": "Test"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.put(
            f"/api/scans/{scan_id}",
            json={"schedule": "*/2 * * * *"},
            headers=admin_headers,
        )
        assert response.status_code == 422

    def test_update_active_probing(self, client, admin_headers):
        """Updating active_probing_enabled succeeds."""
        create_resp = client.post(
            "/api/scans", json={"name": "Probe Test"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.put(
            f"/api/scans/{scan_id}",
            json={"active_probing_enabled": True},
            headers=admin_headers,
        )
        assert response.status_code == 200
        assert response.json()["active_probing_enabled"] is True


class TestDeleteScanJob:
    """Tests for DELETE /api/scans/{scan_id} endpoint."""

    def test_delete_requires_auth(self, client):
        """Deleting a scan job without auth returns 401."""
        response = client.delete(f"/api/scans/{uuid4()}")
        assert response.status_code == 401

    def test_delete_requires_admin(self, client, admin_headers, viewer_headers):
        """Deleting a scan job with viewer role returns 403."""
        create_resp = client.post(
            "/api/scans", json={"name": "To Delete"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.delete(
            f"/api/scans/{scan_id}", headers=viewer_headers
        )
        assert response.status_code == 403

    def test_delete_not_found(self, client, admin_headers):
        """Deleting a non-existent scan job returns 404."""
        response = client.delete(
            f"/api/scans/{uuid4()}", headers=admin_headers
        )
        assert response.status_code == 404

    def test_delete_success(self, client, admin_headers, viewer_headers):
        """Deleting a scan job succeeds and removes it."""
        create_resp = client.post(
            "/api/scans", json={"name": "To Delete"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.delete(
            f"/api/scans/{scan_id}", headers=admin_headers
        )
        assert response.status_code == 204

        # Verify it's gone
        get_resp = client.get(f"/api/scans/{scan_id}", headers=viewer_headers)
        assert get_resp.status_code == 404


# --- Manual Trigger Tests ---


class TestManualTrigger:
    """Tests for POST /api/scans/{scan_id}/trigger endpoint."""

    def test_trigger_requires_auth(self, client):
        """Triggering without auth returns 401."""
        response = client.post(f"/api/scans/{uuid4()}/trigger")
        assert response.status_code == 401

    def test_trigger_requires_admin(self, client, admin_headers, viewer_headers):
        """Triggering with viewer role returns 403."""
        create_resp = client.post(
            "/api/scans", json={"name": "Trigger Test"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.post(
            f"/api/scans/{scan_id}/trigger", headers=viewer_headers
        )
        assert response.status_code == 403

    def test_trigger_not_found(self, client, admin_headers):
        """Triggering a non-existent scan job returns 404."""
        response = client.post(
            f"/api/scans/{uuid4()}/trigger", headers=admin_headers
        )
        assert response.status_code == 404

    def test_trigger_success(self, client, admin_headers):
        """Triggering a scan job sets status to running."""
        create_resp = client.post(
            "/api/scans", json={"name": "Manual Scan"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.post(
            f"/api/scans/{scan_id}/trigger", headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert data["scan_job_id"] == scan_id
        assert "5 seconds" in data["message"]
        assert data["triggered_at"] is not None

    def test_trigger_conflict_when_running(self, client, admin_headers):
        """Triggering a scan that's already running returns 409."""
        create_resp = client.post(
            "/api/scans", json={"name": "Running Scan"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        # First trigger succeeds
        client.post(f"/api/scans/{scan_id}/trigger", headers=admin_headers)

        # Second trigger should conflict
        response = client.post(
            f"/api/scans/{scan_id}/trigger", headers=admin_headers
        )
        assert response.status_code == 409
        assert "already running" in response.json()["detail"]

    def test_trigger_creates_history_entry(self, client, admin_headers, viewer_headers):
        """Triggering creates a scan history entry."""
        create_resp = client.post(
            "/api/scans", json={"name": "History Test"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        # Trigger the scan
        client.post(f"/api/scans/{scan_id}/trigger", headers=admin_headers)

        # Check history
        response = client.get(
            f"/api/scans/{scan_id}/history", headers=viewer_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["status"] == "running"


# --- Scan History Tests ---


class TestScanHistory:
    """Tests for GET /api/scans/{scan_id}/history endpoint."""

    def test_history_requires_auth(self, client):
        """Getting history without auth returns 401."""
        response = client.get(f"/api/scans/{uuid4()}/history")
        assert response.status_code == 401

    def test_history_not_found(self, client, viewer_headers):
        """Getting history for non-existent scan returns 404."""
        response = client.get(
            f"/api/scans/{uuid4()}/history", headers=viewer_headers
        )
        assert response.status_code == 404

    def test_history_empty(self, client, admin_headers, viewer_headers):
        """Getting history when none exists returns empty list."""
        create_resp = client.post(
            "/api/scans", json={"name": "No History"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.get(
            f"/api/scans/{scan_id}/history", headers=viewer_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["page_size"] == 20

    def test_history_default_pagination(self, client, admin_headers, viewer_headers):
        """Default page size for history is 20."""
        create_resp = client.post(
            "/api/scans", json={"name": "Paginated"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.get(
            f"/api/scans/{scan_id}/history", headers=viewer_headers
        )
        assert response.status_code == 200
        assert response.json()["page_size"] == 20

    def test_history_max_page_size_100(self, client, admin_headers, viewer_headers):
        """Page size > 100 for history returns 422."""
        create_resp = client.post(
            "/api/scans", json={"name": "Max Page"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.get(
            f"/api/scans/{scan_id}/history?page_size=101", headers=viewer_headers
        )
        assert response.status_code == 422

    def test_history_custom_pagination(self, client, admin_headers, viewer_headers):
        """Custom page size for history is respected."""
        create_resp = client.post(
            "/api/scans", json={"name": "Custom Page"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        # Trigger multiple times (need to reset status between triggers)
        # First trigger
        client.post(f"/api/scans/{scan_id}/trigger", headers=admin_headers)

        response = client.get(
            f"/api/scans/{scan_id}/history?page_size=5", headers=viewer_headers
        )
        assert response.status_code == 200
        assert response.json()["page_size"] == 5

    def test_history_date_range_filtering(self, client, admin_headers, viewer_headers):
        """History can be filtered by date range."""
        create_resp = client.post(
            "/api/scans", json={"name": "Date Filter"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        # Trigger to create a history entry
        client.post(f"/api/scans/{scan_id}/trigger", headers=admin_headers)

        # Filter with future start_date should return nothing
        future = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        response = client.get(
            f"/api/scans/{scan_id}/history",
            params={"start_date": future},
            headers=viewer_headers,
        )
        assert response.status_code == 200
        assert response.json()["total"] == 0

    def test_history_date_range_includes_results(self, client, admin_headers, viewer_headers):
        """History with date range that includes entries returns them."""
        create_resp = client.post(
            "/api/scans", json={"name": "Date Include"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        # Trigger to create a history entry
        client.post(f"/api/scans/{scan_id}/trigger", headers=admin_headers)

        # Filter with past start_date should include the entry
        past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        response = client.get(
            f"/api/scans/{scan_id}/history",
            params={"start_date": past},
            headers=viewer_headers,
        )
        assert response.status_code == 200
        assert response.json()["total"] == 1

    def test_history_viewer_can_access(self, client, admin_headers, viewer_headers):
        """Viewer role can access scan history (read access)."""
        create_resp = client.post(
            "/api/scans", json={"name": "Viewer Access"}, headers=admin_headers
        )
        scan_id = create_resp.json()["id"]

        response = client.get(
            f"/api/scans/{scan_id}/history", headers=viewer_headers
        )
        assert response.status_code == 200
