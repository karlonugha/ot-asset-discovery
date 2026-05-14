"""WebSocket endpoint for real-time alert streaming.

Implements the /ws/alerts endpoint that pushes alert events to connected
clients within 2 seconds of generation.

Authentication is performed via a token query parameter since WebSocket
connections cannot use standard HTTP Authorization headers.

Requirements: 5.5
"""

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from app.api.auth import decode_access_token, AuthError
from app.api.websocket_manager import alert_ws_manager

ws_router = APIRouter(tags=["websocket"])


@ws_router.websocket("/ws/alerts")
async def alert_websocket(
    websocket: WebSocket,
    token: str = Query(default=None),
) -> None:
    """WebSocket endpoint for real-time alert streaming.

    Clients connect to receive alert events as they are generated.
    Authentication is performed via a `token` query parameter containing
    a valid JWT token. Both viewer and admin roles can subscribe.

    The endpoint pushes alert events within 2 seconds of generation
    per Requirement 5.5.

    Message format (server -> client):
    ```json
    {
        "type": "alert",
        "data": {
            "id": "uuid",
            "alert_type": "new_device",
            "severity": "HIGH",
            "device_id": "uuid or null",
            "details": {...},
            "generated_at": "ISO 8601 timestamp"
        }
    }
    ```

    Connection flow:
    1. Client connects with ?token=<jwt>
    2. Server validates token
    3. On success: connection accepted, client receives alerts
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
        token_data = decode_access_token(token)
    except AuthError as e:
        await websocket.close(code=4001, reason=e.detail)
        return

    # Accept connection and register with the manager
    await alert_ws_manager.connect(websocket)

    try:
        # Keep the connection alive by reading messages (ping/pong)
        while True:
            # Wait for client messages (used for keepalive/ping)
            # The client can send ping messages; we just acknowledge
            data = await websocket.receive_text()
            # Echo back pong for keepalive
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await alert_ws_manager.disconnect(websocket)
