"""Async event bus for decoupled component communication.

Implements a pub/sub pattern that allows components to communicate
without direct dependencies. Events are dispatched asynchronously
to all registered handlers.

Supported events:
- "device_updated" → triggers ChangeDetector.process_fingerprint() and RiskScorer.calculate_score()
- "topology_updated" → triggers RiskScorer recalculation (peer count changed)
- "alert_generated" → triggers WebSocket broadcast and database persistence
- "scan_completed" → triggers scan history recording

Requirements: 5.7, 7.1, 7.7, 11.2
"""

import asyncio
import logging
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)

# Type alias for async event handlers
EventHandler = Callable[[dict[str, Any]], Awaitable[None]]

# Supported event types
DEVICE_UPDATED = "device_updated"
TOPOLOGY_UPDATED = "topology_updated"
ALERT_GENERATED = "alert_generated"
SCAN_COMPLETED = "scan_completed"

ALL_EVENT_TYPES = frozenset({
    DEVICE_UPDATED,
    TOPOLOGY_UPDATED,
    ALERT_GENERATED,
    SCAN_COMPLETED,
})


class EventBus:
    """Async event bus implementing the pub/sub pattern.

    Components subscribe to specific event types by registering handler
    callbacks. When an event is emitted, all registered handlers for that
    event type are invoked concurrently.

    Handlers that raise exceptions are logged but do not prevent other
    handlers from executing (fault isolation).

    Thread-safe for use with asyncio (single event loop).

    Requirements: 5.7, 7.1, 7.7, 11.2
    """

    def __init__(self) -> None:
        """Initialize the event bus with empty subscriber registry."""
        self._subscribers: dict[str, list[EventHandler]] = {}
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Register a handler for a specific event type.

        Args:
            event_type: The event type to subscribe to. Must be one of
                the supported event types (DEVICE_UPDATED, TOPOLOGY_UPDATED,
                ALERT_GENERATED, SCAN_COMPLETED).
            handler: Async callable that receives the event payload dict.

        Raises:
            ValueError: If event_type is not a recognized event type.
        """
        if event_type not in ALL_EVENT_TYPES:
            raise ValueError(
                f"Unknown event type '{event_type}'. "
                f"Supported types: {sorted(ALL_EVENT_TYPES)}"
            )
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
        logger.debug(
            "Handler %s subscribed to event '%s'",
            handler.__name__ if hasattr(handler, "__name__") else repr(handler),
            event_type,
        )

    def unsubscribe(self, event_type: str, handler: EventHandler) -> bool:
        """Remove a handler from a specific event type.

        Args:
            event_type: The event type to unsubscribe from.
            handler: The handler to remove.

        Returns:
            True if the handler was found and removed, False otherwise.
        """
        if event_type not in self._subscribers:
            return False
        try:
            self._subscribers[event_type].remove(handler)
            logger.debug(
                "Handler %s unsubscribed from event '%s'",
                handler.__name__ if hasattr(handler, "__name__") else repr(handler),
                event_type,
            )
            return True
        except ValueError:
            return False

    async def emit(self, event_type: str, payload: dict[str, Any]) -> list[Exception]:
        """Emit an event to all registered handlers.

        All handlers for the event type are invoked concurrently using
        asyncio.gather. Exceptions from individual handlers are caught
        and logged but do not prevent other handlers from executing.

        Args:
            event_type: The event type being emitted.
            payload: Dictionary containing event-specific data.

        Returns:
            List of exceptions raised by handlers (empty if all succeeded).

        Raises:
            ValueError: If event_type is not a recognized event type.
        """
        if event_type not in ALL_EVENT_TYPES:
            raise ValueError(
                f"Unknown event type '{event_type}'. "
                f"Supported types: {sorted(ALL_EVENT_TYPES)}"
            )

        handlers = self._subscribers.get(event_type, [])
        if not handlers:
            logger.debug("No handlers registered for event '%s'", event_type)
            return []

        logger.debug(
            "Emitting event '%s' to %d handler(s)", event_type, len(handlers)
        )

        exceptions: list[Exception] = []

        # Execute all handlers concurrently
        results = await asyncio.gather(
            *[self._invoke_handler(handler, event_type, payload) for handler in handlers],
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception):
                exceptions.append(result)

        if exceptions:
            logger.warning(
                "Event '%s' had %d handler error(s)", event_type, len(exceptions)
            )

        return exceptions

    async def emit_nowait(self, event_type: str, payload: dict[str, Any]) -> None:
        """Emit an event without waiting for handlers to complete.

        Creates a background task to dispatch the event. Useful for
        fire-and-forget scenarios where the caller doesn't need to wait
        for handler completion.

        Args:
            event_type: The event type being emitted.
            payload: Dictionary containing event-specific data.

        Raises:
            ValueError: If event_type is not a recognized event type.
        """
        if event_type not in ALL_EVENT_TYPES:
            raise ValueError(
                f"Unknown event type '{event_type}'. "
                f"Supported types: {sorted(ALL_EVENT_TYPES)}"
            )
        asyncio.create_task(self.emit(event_type, payload))

    async def _invoke_handler(
        self, handler: EventHandler, event_type: str, payload: dict[str, Any]
    ) -> None:
        """Invoke a single handler with error isolation.

        Args:
            handler: The async handler to invoke.
            event_type: The event type (for logging context).
            payload: The event payload to pass to the handler.
        """
        try:
            await handler(payload)
        except Exception as e:
            handler_name = (
                handler.__name__ if hasattr(handler, "__name__") else repr(handler)
            )
            logger.error(
                "Handler '%s' failed for event '%s': %s",
                handler_name,
                event_type,
                e,
                exc_info=True,
            )
            raise

    def get_subscriber_count(self, event_type: str) -> int:
        """Get the number of subscribers for an event type.

        Args:
            event_type: The event type to check.

        Returns:
            Number of registered handlers for the event type.
        """
        return len(self._subscribers.get(event_type, []))

    def clear(self) -> None:
        """Remove all subscribers from all event types.

        Useful for testing or shutdown cleanup.
        """
        self._subscribers.clear()
        logger.debug("All event bus subscribers cleared")


# Global singleton event bus instance
event_bus = EventBus()
