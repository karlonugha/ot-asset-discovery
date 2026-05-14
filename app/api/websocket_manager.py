"""WebSocket connection manager for real-time alert broadcasting.

Manages connected WebSocket clients and broadcasts alert events
within 2 seconds of generation per Requirement 5.5.

Requirements: 5.5
"""

import asyncio
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import WebSocket


class _JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles UUID and datetime objects."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class WebSocketManager:
    """Manages WebSocket connections and broadcasts alert events.

    Maintains a set of active WebSocket connections and provides
    methods to broadcast alert events to all connected clients.
    Alert events are pushed within 2 seconds of generation (Requirement 5.5).
    """

    def __init__(self) -> None:
        """Initialize the WebSocket manager with an empty connection set."""
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def active_connections(self) -> int:
        """Return the number of active WebSocket connections."""
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection.

        Args:
            websocket: The WebSocket connection to register.
        """
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection from the active set.

        Args:
            websocket: The WebSocket connection to remove.
        """
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast_alert(self, alert_data: dict) -> None:
        """Broadcast an alert event to all connected WebSocket clients.

        Sends the alert as a JSON message to all active connections.
        Disconnects clients that fail to receive the message.

        Args:
            alert_data: Dictionary containing the alert data to broadcast.
        """
        if not self._connections:
            return

        message = json.dumps(
            {"type": "alert", "data": alert_data},
            cls=_JSONEncoder,
        )

        # Collect connections that need to be removed
        disconnected: set[WebSocket] = set()

        async with self._lock:
            for websocket in self._connections.copy():
                try:
                    await websocket.send_text(message)
                except Exception:
                    disconnected.add(websocket)

            # Clean up disconnected clients
            self._connections -= disconnected

    async def broadcast_json(self, message: dict) -> None:
        """Broadcast an arbitrary JSON message to all connected clients.

        Args:
            message: Dictionary to serialize and send.
        """
        if not self._connections:
            return

        text = json.dumps(message, cls=_JSONEncoder)
        disconnected: set[WebSocket] = set()

        async with self._lock:
            for websocket in self._connections.copy():
                try:
                    await websocket.send_text(text)
                except Exception:
                    disconnected.add(websocket)

            self._connections -= disconnected


# Global singleton instance for alert WebSocket broadcasting
alert_ws_manager = WebSocketManager()
