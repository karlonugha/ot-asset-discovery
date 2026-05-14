"""Topology REST API and WebSocket endpoints.

Implements:
- GET /api/topology returning nodes array and edges array per design schema
- Include stale flag and last_updated when sniffer not running
- WebSocket /ws/topology for new_communication_path event broadcasts

Requirements: 6.2, 6.5
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel, Field

from app.api.auth import TokenData, decode_access_token, AuthError
from app.api.dependencies import require_viewer
from app.api.websocket_manager import WebSocketManager
from app.db.session import async_session_factory
from app.topology.mapper import TopologyMapper


# --- Response Models ---


class TopologyNodeResponse(BaseModel):
    """Response model for a topology node (device)."""

    device_id: UUID
    name: Optional[str] = None
    ip_address: str
    device_type: Optional[str] = None


class TopologyEdgeResponse(BaseModel):
    """Response model for a topology edge (communication path)."""

    source_device_id: UUID
    dest_device_id: UUID
    protocol: str
    packet_count: int = Field(ge=0)
    last_seen: datetime


class TopologyResponse(BaseModel):
    """Response model for the full topology graph.

    Includes a stale flag indicating whether the sniffer is currently running,
    and last_updated timestamp when data was last refreshed.
    """

    nodes: list[TopologyNodeResponse] = Field(default_factory=list)
    edges: list[TopologyEdgeResponse] = Field(default_factory=list)
    stale: bool = False
    last_updated: Optional[datetime] = None


# --- Global instances ---

# WebSocket manager for topology events (new_communication_path broadcasts)
topology_ws_manager = WebSocketManager()

# Global TopologyMapper instance (shared with the discovery engine)
# This will be set by the application startup or discovery engine wiring.
_topology_mapper: Optional[TopologyMapper] = None


def get_topology_mapper() -> TopologyMapper:
    """Get the global TopologyMapper instance.

    Returns the shared TopologyMapper used by the discovery engine.
    If not yet initialized, creates one with the database session factory.

    Returns:
        The TopologyMapper instance.
    """
    global _topology_mapper
    if _topology_mapper is None:
        _topology_mapper = TopologyMapper(session_factory=async_session_factory)
    return _topology_mapper


def set_topology_mapper(mapper: TopologyMapper) -> None:
    """Set the global TopologyMapper instance.

    Used by the discovery engine or application startup to inject
    the shared TopologyMapper.

    Args:
        mapper: The TopologyMapper instance to use.
    """
    global _topology_mapper
    _topology_mapper = mapper


# --- Router ---

topology_router = APIRouter(prefix="/api/topology", tags=["topology"])


@topology_router.get(
    "",
    response_model=TopologyResponse,
    summary="Get network topology",
    description=(
        "Returns the current network topology as a graph with nodes (devices) "
        "and edges (communication paths). Includes a stale flag when the "
        "passive sniffer is not running, and a last_updated timestamp "
        "indicating when data was last refreshed."
    ),
)
async def get_topology(
    _current_user: TokenData = Depends(require_viewer),
) -> TopologyResponse:
    """Get the current network topology graph.

    Returns a JSON response containing:
    - nodes: array of devices with device_id, name, ip_address, device_type
    - edges: array of communication paths with source/dest device IDs,
      protocol, packet_count, and last_seen timestamp
    - stale: true when the passive sniffer is not running (Requirement 6.5)
    - last_updated: timestamp of when topology data was last refreshed

    Args:
        _current_user: Authenticated user (viewer or admin).

    Returns:
        TopologyResponse with the full topology graph.
    """
    mapper = get_topology_mapper()
    topology = await mapper.get_topology()

    # Convert domain models to response models
    nodes = [
        TopologyNodeResponse(
            device_id=node.device_id,
            name=node.name,
            ip_address=node.ip_address,
            device_type=node.device_type,
        )
        for node in topology.nodes
    ]

    edges = [
        TopologyEdgeResponse(
            source_device_id=edge.source_device_id,
            dest_device_id=edge.dest_device_id,
            protocol=edge.protocol,
            packet_count=edge.packet_count,
            last_seen=edge.last_seen,
        )
        for edge in topology.edges
    ]

    return TopologyResponse(
        nodes=nodes,
        edges=edges,
        stale=topology.stale,
        last_updated=topology.last_updated,
    )


# --- WebSocket endpoint for topology events ---

ws_topology_router = APIRouter(tags=["websocket"])


@ws_topology_router.websocket("/ws/topology")
async def topology_websocket(
    websocket: WebSocket,
    token: str = Query(default=None),
) -> None:
    """WebSocket endpoint for real-time topology event streaming.

    Clients connect to receive new_communication_path events as they
    are generated by the TopologyMapper. Authentication is performed
    via a `token` query parameter containing a valid JWT token.

    Message format (server -> client):
    ```json
    {
        "type": "new_communication_path",
        "data": {
            "source_device_id": "uuid",
            "dest_device_id": "uuid",
            "protocol": "modbus_tcp",
            "timestamp": "ISO 8601 timestamp"
        }
    }
    ```

    Connection flow:
    1. Client connects with ?token=<jwt>
    2. Server validates token
    3. On success: connection accepted, client receives topology events
    4. On failure: connection closed with 4001 (auth error)

    Args:
        websocket: The WebSocket connection.
        token: JWT token for authentication (query parameter).
    """
    # Validate authentication token
    if token is None:
        await websocket.close(code=4001, reason="missing token")
        return

    try:
        decode_access_token(token)
    except AuthError as e:
        await websocket.close(code=4001, reason=e.detail)
        return

    # Accept connection and register with the topology WebSocket manager
    await topology_ws_manager.connect(websocket)

    try:
        # Keep the connection alive by reading messages (ping/pong)
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await topology_ws_manager.disconnect(websocket)


async def broadcast_new_communication_path(
    source_device_id: UUID,
    dest_device_id: UUID,
    protocol: str,
    timestamp: Optional[datetime] = None,
) -> None:
    """Broadcast a new_communication_path event to all connected WebSocket clients.

    Called by the discovery engine when the TopologyMapper generates a
    NewCommunicationEvent (Requirement 6.3).

    Args:
        source_device_id: UUID of the source device.
        dest_device_id: UUID of the destination device.
        protocol: Protocol name of the communication path.
        timestamp: Event timestamp (defaults to now if not provided).
    """
    if timestamp is None:
        timestamp = datetime.now()

    await topology_ws_manager.broadcast_json({
        "type": "new_communication_path",
        "data": {
            "source_device_id": str(source_device_id),
            "dest_device_id": str(dest_device_id),
            "protocol": protocol,
            "timestamp": timestamp.isoformat(),
        },
    })
