"""Unit tests for topology REST API and WebSocket endpoints.

Tests:
- GET /api/topology returns nodes and edges per design schema
- Stale flag and last_updated when sniffer not running
- WebSocket /ws/topology authentication and new_communication_path broadcast
- Response model validation
- HTTP-level endpoint tests with TestClient

Requirements: 6.2, 6.5
"""

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth import create_access_token
from app.api.router_topology import (
    TopologyEdgeResponse,
    TopologyNodeResponse,
    TopologyResponse,
    broadcast_new_communication_path,
    get_topology_mapper,
    set_topology_mapper,
    topology_router,
    topology_ws_manager,
    ws_topology_router,
)
from app.api.websocket_manager import WebSocketManager
from app.models.domain import TopologyEdge, TopologyGraph, TopologyNode
from app.topology.mapper import TopologyMapper


# --- Response Model Tests ---


class TestTopologyResponseModels:
    """Tests for topology response Pydantic models."""

    def test_topology_node_response(self):
        """TopologyNodeResponse correctly serializes node data."""
        device_id = uuid.uuid4()
        node = TopologyNodeResponse(
            device_id=device_id,
            name="192.168.1.10 - Siemens",
            ip_address="192.168.1.10",
            device_type="PLC",
        )
        assert node.device_id == device_id
        assert node.name == "192.168.1.10 - Siemens"
        assert node.ip_address == "192.168.1.10"
        assert node.device_type == "PLC"

    def test_topology_node_response_optional_fields(self):
        """TopologyNodeResponse allows optional name and device_type."""
        device_id = uuid.uuid4()
        node = TopologyNodeResponse(
            device_id=device_id,
            ip_address="10.0.0.5",
        )
        assert node.name is None
        assert node.device_type is None

    def test_topology_edge_response(self):
        """TopologyEdgeResponse correctly serializes edge data."""
        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        edge = TopologyEdgeResponse(
            source_device_id=src_id,
            dest_device_id=dst_id,
            protocol="modbus_tcp",
            packet_count=42,
            last_seen=now,
        )
        assert edge.source_device_id == src_id
        assert edge.dest_device_id == dst_id
        assert edge.protocol == "modbus_tcp"
        assert edge.packet_count == 42
        assert edge.last_seen == now

    def test_topology_response_with_stale_flag(self):
        """TopologyResponse includes stale flag and last_updated."""
        now = datetime.now(timezone.utc)
        response = TopologyResponse(
            nodes=[],
            edges=[],
            stale=True,
            last_updated=now,
        )
        assert response.stale is True
        assert response.last_updated == now
        assert response.nodes == []
        assert response.edges == []

    def test_topology_response_not_stale(self):
        """TopologyResponse stale defaults to False."""
        response = TopologyResponse(
            nodes=[],
            edges=[],
        )
        assert response.stale is False
        assert response.last_updated is None

    def test_topology_response_full_graph(self):
        """TopologyResponse correctly represents a full topology graph."""
        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        nodes = [
            TopologyNodeResponse(
                device_id=src_id,
                name="PLC-1",
                ip_address="192.168.1.10",
                device_type="PLC",
            ),
            TopologyNodeResponse(
                device_id=dst_id,
                name="HMI-1",
                ip_address="192.168.1.20",
                device_type="HMI",
            ),
        ]
        edges = [
            TopologyEdgeResponse(
                source_device_id=src_id,
                dest_device_id=dst_id,
                protocol="s7comm",
                packet_count=100,
                last_seen=now,
            ),
        ]

        response = TopologyResponse(
            nodes=nodes,
            edges=edges,
            stale=False,
            last_updated=now,
        )

        assert len(response.nodes) == 2
        assert len(response.edges) == 1
        assert response.edges[0].protocol == "s7comm"


# --- Topology Mapper Integration Tests ---


class TestGetTopologyEndpoint:
    """Tests for GET /api/topology endpoint logic."""

    @pytest.mark.asyncio
    async def test_get_topology_returns_stale_when_sniffer_not_running(self):
        """Topology returns stale=True when sniffer is not running."""
        mapper = TopologyMapper(session_factory=None)
        # Sniffer is not running by default
        assert mapper.sniffer_running is False

        topology = await mapper.get_topology()
        assert topology.stale is True

    @pytest.mark.asyncio
    async def test_get_topology_returns_not_stale_when_sniffer_running(self):
        """Topology returns stale=False when sniffer is running."""
        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        topology = await mapper.get_topology()
        assert topology.stale is False

    @pytest.mark.asyncio
    async def test_get_topology_includes_last_updated(self):
        """Topology includes last_updated timestamp after recording communication."""
        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        await mapper.record_communication(src_id, dst_id, "modbus_tcp")

        topology = await mapper.get_topology()
        assert topology.last_updated is not None

    @pytest.mark.asyncio
    async def test_get_topology_returns_nodes_and_edges(self):
        """Topology returns nodes and edges from recorded communications."""
        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        await mapper.record_communication(src_id, dst_id, "ethernetip")

        topology = await mapper.get_topology()
        assert len(topology.edges) == 1
        assert topology.edges[0].source_device_id == src_id
        assert topology.edges[0].dest_device_id == dst_id
        assert topology.edges[0].protocol == "ethernetip"
        assert topology.edges[0].packet_count == 1

    @pytest.mark.asyncio
    async def test_get_topology_empty_when_no_communications(self):
        """Topology returns empty nodes and edges when no communications recorded."""
        mapper = TopologyMapper(session_factory=None)
        topology = await mapper.get_topology()
        assert topology.nodes == []
        assert topology.edges == []

    @pytest.mark.asyncio
    async def test_get_topology_stale_with_last_updated_none_initially(self):
        """Topology returns stale=True and last_updated=None when no data exists."""
        mapper = TopologyMapper(session_factory=None)
        topology = await mapper.get_topology()
        assert topology.stale is True
        assert topology.last_updated is None


# --- Topology Mapper Setter/Getter Tests ---


class TestTopologyMapperGlobal:
    """Tests for the global topology mapper getter/setter."""

    def test_set_and_get_topology_mapper(self):
        """set_topology_mapper and get_topology_mapper work correctly."""
        mapper = TopologyMapper(session_factory=None)
        set_topology_mapper(mapper)
        assert get_topology_mapper() is mapper
        # Clean up
        set_topology_mapper(None)


# --- WebSocket Topology Tests ---


class TestTopologyWebSocket:
    """Tests for WebSocket /ws/topology endpoint."""

    @pytest.mark.asyncio
    async def test_ws_rejects_missing_token(self):
        """WebSocket connection is rejected when no token is provided."""
        from app.api.router_topology import topology_websocket

        ws = AsyncMock()
        await topology_websocket(websocket=ws, token=None)
        ws.close.assert_awaited_once_with(code=4001, reason="missing token")

    @pytest.mark.asyncio
    async def test_ws_rejects_invalid_token(self):
        """WebSocket connection is rejected with invalid JWT."""
        from app.api.router_topology import topology_websocket

        ws = AsyncMock()
        await topology_websocket(websocket=ws, token="invalid.jwt.token")
        ws.close.assert_awaited_once()
        call_args = ws.close.call_args
        assert call_args[1]["code"] == 4001

    @pytest.mark.asyncio
    async def test_ws_accepts_valid_token(self):
        """WebSocket connection is accepted with a valid JWT."""
        from app.api.auth import create_access_token
        from app.api.router_topology import topology_websocket

        token = create_access_token(username="testuser", role="viewer")
        ws = AsyncMock()
        # Simulate disconnect after accept
        ws.receive_text.side_effect = Exception("disconnect")

        await topology_websocket(websocket=ws, token=token)
        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ws_handles_ping_pong(self):
        """WebSocket responds to ping with pong."""
        from app.api.auth import create_access_token
        from app.api.router_topology import topology_websocket

        token = create_access_token(username="testuser", role="admin")
        ws = AsyncMock()

        call_count = 0

        async def mock_receive():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "ping"
            raise Exception("disconnect")

        ws.receive_text.side_effect = mock_receive

        await topology_websocket(websocket=ws, token=token)
        ws.send_text.assert_awaited_once_with('{"type": "pong"}')


# --- Broadcast Tests ---


class TestTopologyBroadcast:
    """Tests for new_communication_path event broadcasting."""

    @pytest.mark.asyncio
    async def test_broadcast_new_communication_path(self):
        """broadcast_new_communication_path sends correct message format."""
        ws = AsyncMock()
        await topology_ws_manager.connect(ws)

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        await broadcast_new_communication_path(
            source_device_id=src_id,
            dest_device_id=dst_id,
            protocol="dnp3",
            timestamp=now,
        )

        ws.send_text.assert_awaited_once()
        sent_msg = json.loads(ws.send_text.call_args[0][0])
        assert sent_msg["type"] == "new_communication_path"
        assert sent_msg["data"]["source_device_id"] == str(src_id)
        assert sent_msg["data"]["dest_device_id"] == str(dst_id)
        assert sent_msg["data"]["protocol"] == "dnp3"
        assert sent_msg["data"]["timestamp"] == now.isoformat()

        # Clean up
        await topology_ws_manager.disconnect(ws)

    @pytest.mark.asyncio
    async def test_broadcast_no_connections(self):
        """Broadcasting with no connections does not raise."""
        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        # Should not raise
        await broadcast_new_communication_path(
            source_device_id=src_id,
            dest_device_id=dst_id,
            protocol="modbus_tcp",
        )

    @pytest.mark.asyncio
    async def test_broadcast_uses_default_timestamp(self):
        """broadcast_new_communication_path uses current time when no timestamp given."""
        ws = AsyncMock()
        await topology_ws_manager.connect(ws)

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()

        await broadcast_new_communication_path(
            source_device_id=src_id,
            dest_device_id=dst_id,
            protocol="s7comm",
        )

        ws.send_text.assert_awaited_once()
        sent_msg = json.loads(ws.send_text.call_args[0][0])
        assert sent_msg["data"]["timestamp"] is not None

        # Clean up
        await topology_ws_manager.disconnect(ws)

    @pytest.mark.asyncio
    async def test_broadcast_multiple_clients(self):
        """broadcast_new_communication_path sends to all connected clients."""
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        await topology_ws_manager.connect(ws1)
        await topology_ws_manager.connect(ws2)

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()

        await broadcast_new_communication_path(
            source_device_id=src_id,
            dest_device_id=dst_id,
            protocol="ethernetip",
        )

        ws1.send_text.assert_awaited_once()
        ws2.send_text.assert_awaited_once()

        # Both should receive the same message
        msg1 = json.loads(ws1.send_text.call_args[0][0])
        msg2 = json.loads(ws2.send_text.call_args[0][0])
        assert msg1 == msg2
        assert msg1["type"] == "new_communication_path"

        # Clean up
        await topology_ws_manager.disconnect(ws1)
        await topology_ws_manager.disconnect(ws2)


# --- HTTP-Level Endpoint Tests ---


@pytest.fixture
def topology_test_app():
    """Create a test FastAPI app with the topology router and a mock mapper."""
    app = FastAPI()
    app.include_router(topology_router)
    app.include_router(ws_topology_router)
    return app


@pytest.fixture
def topology_mapper_sniffer_stopped():
    """Create a TopologyMapper with sniffer not running (stale data)."""
    mapper = TopologyMapper(session_factory=None)
    # sniffer_running defaults to False
    return mapper


@pytest.fixture
def topology_mapper_sniffer_running():
    """Create a TopologyMapper with sniffer running (fresh data)."""
    mapper = TopologyMapper(session_factory=None)
    mapper.sniffer_running = True
    return mapper


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


class TestTopologyHTTPEndpoint:
    """HTTP-level tests for GET /api/topology using TestClient."""

    def test_topology_requires_auth(self, topology_test_app):
        """GET /api/topology without auth returns 401."""
        client = TestClient(topology_test_app)
        response = client.get("/api/topology")
        assert response.status_code == 401

    def test_topology_rejects_invalid_token(self, topology_test_app):
        """GET /api/topology with invalid token returns 401."""
        client = TestClient(topology_test_app)
        response = client.get(
            "/api/topology",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert response.status_code == 401

    def test_topology_viewer_can_access(
        self, topology_test_app, topology_mapper_sniffer_stopped, viewer_headers
    ):
        """Viewer role can access GET /api/topology (read-only)."""
        set_topology_mapper(topology_mapper_sniffer_stopped)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200

        # Clean up
        set_topology_mapper(None)

    def test_topology_admin_can_access(
        self, topology_test_app, topology_mapper_sniffer_stopped, admin_headers
    ):
        """Admin role can access GET /api/topology."""
        set_topology_mapper(topology_mapper_sniffer_stopped)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=admin_headers)
        assert response.status_code == 200

        # Clean up
        set_topology_mapper(None)

    def test_topology_returns_stale_when_sniffer_not_running(
        self, topology_test_app, topology_mapper_sniffer_stopped, viewer_headers
    ):
        """GET /api/topology returns stale=True when sniffer is not running (Req 6.5)."""
        set_topology_mapper(topology_mapper_sniffer_stopped)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["stale"] is True
        assert data["last_updated"] is None

        # Clean up
        set_topology_mapper(None)

    def test_topology_returns_not_stale_when_sniffer_running(
        self, topology_test_app, topology_mapper_sniffer_running, viewer_headers
    ):
        """GET /api/topology returns stale=False when sniffer is running."""
        set_topology_mapper(topology_mapper_sniffer_running)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["stale"] is False

        # Clean up
        set_topology_mapper(None)

    def test_topology_returns_empty_graph(
        self, topology_test_app, topology_mapper_sniffer_stopped, viewer_headers
    ):
        """GET /api/topology returns empty nodes and edges when no data."""
        set_topology_mapper(topology_mapper_sniffer_stopped)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["nodes"] == []
        assert data["edges"] == []

        # Clean up
        set_topology_mapper(None)

    def test_topology_returns_nodes_and_edges(
        self, topology_test_app, viewer_headers
    ):
        """GET /api/topology returns nodes and edges from recorded communications."""
        import asyncio

        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        asyncio.run(mapper.record_communication(src_id, dst_id, "modbus_tcp"))

        set_topology_mapper(mapper)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()

        # Verify nodes array
        assert len(data["nodes"]) == 2
        node_ids = {node["device_id"] for node in data["nodes"]}
        assert str(src_id) in node_ids
        assert str(dst_id) in node_ids

        # Verify edges array
        assert len(data["edges"]) == 1
        edge = data["edges"][0]
        assert edge["source_device_id"] == str(src_id)
        assert edge["dest_device_id"] == str(dst_id)
        assert edge["protocol"] == "modbus_tcp"
        assert edge["packet_count"] == 1
        assert edge["last_seen"] is not None

        # Clean up
        set_topology_mapper(None)

    def test_topology_response_schema_structure(
        self, topology_test_app, viewer_headers
    ):
        """GET /api/topology response conforms to the design schema."""
        import asyncio

        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        asyncio.run(mapper.record_communication(src_id, dst_id, "s7comm"))
        asyncio.run(mapper.record_communication(src_id, dst_id, "s7comm"))

        set_topology_mapper(mapper)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()

        # Validate top-level keys per design schema
        assert "nodes" in data
        assert "edges" in data
        assert "stale" in data
        assert "last_updated" in data

        # Validate node schema
        for node in data["nodes"]:
            assert "device_id" in node
            assert "ip_address" in node
            # name and device_type are optional
            assert "name" in node or node.get("name") is None
            assert "device_type" in node or node.get("device_type") is None

        # Validate edge schema
        for edge in data["edges"]:
            assert "source_device_id" in edge
            assert "dest_device_id" in edge
            assert "protocol" in edge
            assert "packet_count" in edge
            assert "last_seen" in edge

        # Verify packet count accumulated
        assert data["edges"][0]["packet_count"] == 2

        # Clean up
        set_topology_mapper(None)

    def test_topology_multiple_edges(
        self, topology_test_app, viewer_headers
    ):
        """GET /api/topology returns multiple edges for different communication paths."""
        import asyncio

        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        device_a = uuid.uuid4()
        device_b = uuid.uuid4()
        device_c = uuid.uuid4()

        # Record different communication paths
        asyncio.run(mapper.record_communication(device_a, device_b, "modbus_tcp"))
        asyncio.run(mapper.record_communication(device_b, device_c, "ethernetip"))
        asyncio.run(mapper.record_communication(device_a, device_c, "dnp3"))

        set_topology_mapper(mapper)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()

        # Should have 3 nodes and 3 edges
        assert len(data["nodes"]) == 3
        assert len(data["edges"]) == 3

        # Verify all protocols present
        protocols = {edge["protocol"] for edge in data["edges"]}
        assert protocols == {"modbus_tcp", "ethernetip", "dnp3"}

        # Clean up
        set_topology_mapper(None)

    def test_topology_stale_with_last_updated_after_communication(
        self, topology_test_app, viewer_headers
    ):
        """When sniffer stops after recording data, stale=True with last_updated set."""
        import asyncio

        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        src_id = uuid.uuid4()
        dst_id = uuid.uuid4()
        asyncio.run(mapper.record_communication(src_id, dst_id, "modbus_tcp"))

        # Stop the sniffer
        mapper.sniffer_running = False

        set_topology_mapper(mapper)
        client = TestClient(topology_test_app)

        response = client.get("/api/topology", headers=viewer_headers)
        assert response.status_code == 200
        data = response.json()

        # Should be stale but have last_updated
        assert data["stale"] is True
        assert data["last_updated"] is not None
        # Should still return the recorded data
        assert len(data["edges"]) == 1

        # Clean up
        set_topology_mapper(None)


class TestTopologyWebSocketHTTP:
    """HTTP-level WebSocket tests using TestClient."""

    def test_ws_topology_rejects_no_token(self, topology_test_app):
        """WebSocket /ws/topology rejects connection without token."""
        client = TestClient(topology_test_app)
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/topology"):
                pass

    def test_ws_topology_accepts_valid_token(self, topology_test_app, viewer_token):
        """WebSocket /ws/topology accepts connection with valid token."""
        client = TestClient(topology_test_app)
        with client.websocket_connect(f"/ws/topology?token={viewer_token}") as ws:
            # Send ping and expect pong
            ws.send_text("ping")
            response = ws.receive_text()
            data = json.loads(response)
            assert data["type"] == "pong"

    def test_ws_topology_admin_can_connect(self, topology_test_app, admin_token):
        """WebSocket /ws/topology accepts admin connections."""
        client = TestClient(topology_test_app)
        with client.websocket_connect(f"/ws/topology?token={admin_token}") as ws:
            ws.send_text("ping")
            response = ws.receive_text()
            data = json.loads(response)
            assert data["type"] == "pong"
