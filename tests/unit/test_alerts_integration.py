"""Integration tests for alert REST API endpoint with FastAPI TestClient.

Tests the HTTP-level behavior of alert endpoints:
- GET /api/alerts with filtering by severity, device, alert type, time range
- Pagination (max 100 per page, sorted by timestamp desc)
- RBAC enforcement (viewer can read alerts)
- WebSocket /ws/alerts endpoint with TestClient

Requirements: 5.5, 5.6

Uses SQLite with type compilation overrides for PostgreSQL-specific types.
"""

import json
import uuid
import pytest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import MACADDR, INET, CIDR, JSONB

from app.api.auth import create_access_token
from app.api.router_alerts import alerts_router
from app.api.ws_alerts import ws_router
from app.db.session import get_session
from app.models.database import Alert


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
def test_app():
    """Create a test FastAPI app with the alerts router and WebSocket."""

    app = FastAPI()
    app.include_router(alerts_router)
    app.include_router(ws_router)

    # Create engine and session factory
    # Use json_serializer/json_deserializer to handle JSONB columns properly
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
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
    """Set up the database tables using raw DDL for SQLite compatibility."""
    import asyncio

    async def _setup():
        async with test_app._test_engine.begin() as conn:
            await conn.execute(text("""
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
            await conn.execute(text("""
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


def _seed_alerts(test_app):
    """Seed the database with test alerts using raw SQL."""
    import asyncio

    now = datetime.now(timezone.utc)
    device_uuid = uuid.uuid4()
    # SQLAlchemy UUID type on SQLite stores as 32-char hex (no dashes)
    device_id = device_uuid.hex
    alerts_data = []
    alert_details = [
        ("new_device", "HIGH", device_id, {"ip_address": "10.0.0.1", "mac_address": "AA:BB:CC:DD:EE:01"}, now - timedelta(hours=5)),
        ("firmware_change", "HIGH", device_id, {"previous_version": "1.0", "new_version": "2.0"}, now - timedelta(hours=4)),
        ("device_disappeared", "MEDIUM", device_id, {"last_seen": (now - timedelta(hours=25)).isoformat()}, now - timedelta(hours=3)),
        ("new_protocol", "MEDIUM", device_id, {"protocol": "s7comm"}, now - timedelta(hours=2)),
        ("risk_score_change", "LOW", None, {"previous_score": 30, "new_score": 55}, now - timedelta(hours=1)),
        ("scan_failed", "CRITICAL", None, {"reason": "Network interface unavailable"}, now),
    ]

    for alert_type, severity, dev_id, details, generated_at in alert_details:
        alerts_data.append({
            "id": uuid.uuid4().hex,
            "alert_type": alert_type,
            "severity": severity,
            "device_id": dev_id,
            "details": details,
            "generated_at": generated_at,
        })

    async def _seed():
        async with test_app._test_session_factory() as session:
            # Insert a device first for foreign key reference
            await session.execute(text("""
                INSERT INTO devices (id, mac_address, ip_address, vendor, model, firmware_version,
                    device_type, protocols, risk_score, first_seen, last_seen, created_at, updated_at)
                VALUES (:id, :mac, :ip, :vendor, :model, :fw, :dtype, :protos, :risk,
                    :first_seen, :last_seen, :created_at, :updated_at)
            """), {
                "id": device_id,
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "10.0.0.1",
                "vendor": "Siemens",
                "model": "S7-1200",
                "fw": "4.5.0",
                "dtype": "PLC",
                "protos": json.dumps(["modbus_tcp", "s7comm"]),
                "risk": 45,
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            })

            for alert_data in alerts_data:
                await session.execute(text("""
                    INSERT INTO alerts (id, alert_type, severity, device_id, details, generated_at)
                    VALUES (:id, :alert_type, :severity, :device_id, :details, :generated_at)
                """), {
                    "id": alert_data["id"],
                    "alert_type": alert_data["alert_type"],
                    "severity": alert_data["severity"],
                    "device_id": alert_data["device_id"],
                    "details": json.dumps(alert_data["details"]),
                    "generated_at": alert_data["generated_at"].strftime("%Y-%m-%d %H:%M:%S"),
                })
            await session.commit()

    asyncio.run(_seed())
    # Return device_id as a standard UUID string (with dashes) for URL construction
    return alerts_data, str(device_uuid)


class TestAlertEndpointIntegration:
    """Integration tests for GET /api/alerts endpoint."""

    def test_list_alerts_requires_auth(self, client):
        """GET /api/alerts returns 401 without authentication."""
        response = client.get("/api/alerts")
        assert response.status_code == 401

    def test_list_alerts_viewer_access(self, client, viewer_headers, test_app):
        """Viewer role can access alerts (read-only)."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "has_next" in data

    def test_list_alerts_admin_access(self, client, admin_headers, test_app):
        """Admin role can access alerts."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 6

    def test_list_alerts_sorted_by_timestamp_desc(self, client, viewer_headers, test_app):
        """Alerts are sorted by generated_at descending (newest first)."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        alerts = data["alerts"]
        assert len(alerts) == 6

        # Verify descending order
        timestamps = [a["generated_at"] for a in alerts]
        for i in range(len(timestamps) - 1):
            assert timestamps[i] >= timestamps[i + 1], (
                f"Alert at index {i} should be newer than index {i+1}"
            )

    def test_filter_by_severity(self, client, viewer_headers, test_app):
        """Filter alerts by severity level."""
        _seed_alerts(test_app)

        # Filter HIGH severity
        response = client.get("/api/alerts?severity=HIGH", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        for alert in data["alerts"]:
            assert alert["severity"] == "HIGH"

        # Filter MEDIUM severity
        response = client.get("/api/alerts?severity=MEDIUM", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        for alert in data["alerts"]:
            assert alert["severity"] == "MEDIUM"

        # Filter CRITICAL severity
        response = client.get("/api/alerts?severity=CRITICAL", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["alerts"][0]["severity"] == "CRITICAL"

    def test_filter_by_alert_type(self, client, viewer_headers, test_app):
        """Filter alerts by alert type."""
        _seed_alerts(test_app)

        response = client.get("/api/alerts?alert_type=new_device", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["alerts"][0]["alert_type"] == "new_device"

        response = client.get("/api/alerts?alert_type=firmware_change", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["alerts"][0]["alert_type"] == "firmware_change"

    def test_filter_by_device_id(self, client, viewer_headers, test_app):
        """Filter alerts by device UUID."""
        alerts_data, device_id = _seed_alerts(test_app)

        response = client.get(f"/api/alerts?device_id={device_id}", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        # 4 alerts are associated with the device
        assert data["total"] == 4
        for alert in data["alerts"]:
            # API returns UUID in standard format
            assert alert["device_id"] == device_id

    def test_filter_by_time_range(self, client, viewer_headers, test_app):
        """Filter alerts by time range (start_time and end_time)."""
        _seed_alerts(test_app)
        now = datetime.now(timezone.utc)

        # Get alerts from last 2.5 hours
        start_time = (now - timedelta(hours=2, minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        response = client.get(
            "/api/alerts",
            params={"start_time": start_time},
            headers=viewer_headers,
        )
        assert response.status_code == 200
        data = response.json()
        # Should include alerts from 2h, 1h, and now (3 alerts)
        assert data["total"] == 3

    def test_filter_combined(self, client, viewer_headers, test_app):
        """Multiple filters can be combined (AND logic)."""
        alerts_data, device_id = _seed_alerts(test_app)

        # Filter by severity=HIGH AND device_id
        response = client.get(
            f"/api/alerts?severity=HIGH&device_id={device_id}",
            headers=viewer_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        for alert in data["alerts"]:
            assert alert["severity"] == "HIGH"
            assert alert["device_id"] == device_id

    def test_pagination_default_page_size(self, client, viewer_headers, test_app):
        """Default page size is 100."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["page_size"] == 100
        assert data["page"] == 1

    def test_pagination_custom_page_size(self, client, viewer_headers, test_app):
        """Custom page size is respected."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts?page_size=2", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["page_size"] == 2
        assert len(data["alerts"]) == 2
        assert data["total"] == 6
        assert data["has_next"] is True

    def test_pagination_page_navigation(self, client, viewer_headers, test_app):
        """Page navigation works correctly."""
        _seed_alerts(test_app)

        # Page 1 with size 2
        response = client.get("/api/alerts?page=1&page_size=2", headers=viewer_headers)
        assert response.status_code == 200
        page1 = response.json()
        assert len(page1["alerts"]) == 2
        assert page1["has_next"] is True

        # Page 2 with size 2
        response = client.get("/api/alerts?page=2&page_size=2", headers=viewer_headers)
        assert response.status_code == 200
        page2 = response.json()
        assert len(page2["alerts"]) == 2
        assert page2["has_next"] is True

        # Page 3 with size 2
        response = client.get("/api/alerts?page=3&page_size=2", headers=viewer_headers)
        assert response.status_code == 200
        page3 = response.json()
        assert len(page3["alerts"]) == 2
        assert page3["has_next"] is False

        # Verify no overlap between pages
        page1_ids = {a["id"] for a in page1["alerts"]}
        page2_ids = {a["id"] for a in page2["alerts"]}
        page3_ids = {a["id"] for a in page3["alerts"]}
        assert page1_ids.isdisjoint(page2_ids)
        assert page2_ids.isdisjoint(page3_ids)
        assert page1_ids.isdisjoint(page3_ids)

    def test_page_size_max_100_enforced(self, client, viewer_headers, test_app):
        """Page size cannot exceed 100 (returns 422 validation error)."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts?page_size=101", headers=viewer_headers)
        assert response.status_code == 422

    def test_empty_result_set(self, client, viewer_headers, test_app):
        """Returns empty list when no alerts match filters."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts?severity=LOW&alert_type=new_device", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["alerts"] == []
        assert data["has_next"] is False

    def test_get_single_alert(self, client, viewer_headers, test_app):
        """GET /api/alerts/{alert_id} returns a single alert."""
        alerts_data, _ = _seed_alerts(test_app)
        # Convert hex id to standard UUID format for the URL
        alert_hex = alerts_data[0]["id"]
        alert_uuid = str(uuid.UUID(alert_hex))

        response = client.get(f"/api/alerts/{alert_uuid}", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == alert_uuid
        assert data["alert_type"] == "new_device"
        assert data["severity"] == "HIGH"

    def test_get_nonexistent_alert(self, client, viewer_headers, test_app):
        """GET /api/alerts/{alert_id} returns 404 for non-existent alert."""
        _seed_alerts(test_app)
        fake_id = str(uuid.uuid4())
        response = client.get(f"/api/alerts/{fake_id}", headers=viewer_headers)
        assert response.status_code == 404

    def test_invalid_severity_filter(self, client, viewer_headers, test_app):
        """Invalid severity value returns 422 validation error."""
        _seed_alerts(test_app)
        response = client.get("/api/alerts?severity=INVALID", headers=viewer_headers)
        assert response.status_code == 422


class TestAlertWebSocketIntegration:
    """Integration tests for WebSocket /ws/alerts endpoint."""

    def test_ws_requires_token(self, client):
        """WebSocket connection requires a token query parameter."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/alerts"):
                pass

    def test_ws_rejects_invalid_token(self, client):
        """WebSocket connection is rejected with invalid token."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/alerts?token=invalid.jwt.token"):
                pass

    def test_ws_accepts_valid_viewer_token(self, client, viewer_token):
        """WebSocket connection is accepted with valid viewer token."""
        with client.websocket_connect(f"/ws/alerts?token={viewer_token}") as ws:
            # Connection accepted - send ping to verify
            ws.send_text("ping")
            response = ws.receive_text()
            data = json.loads(response)
            assert data["type"] == "pong"

    def test_ws_accepts_valid_admin_token(self, client, admin_token):
        """WebSocket connection is accepted with valid admin token."""
        with client.websocket_connect(f"/ws/alerts?token={admin_token}") as ws:
            ws.send_text("ping")
            response = ws.receive_text()
            data = json.loads(response)
            assert data["type"] == "pong"
