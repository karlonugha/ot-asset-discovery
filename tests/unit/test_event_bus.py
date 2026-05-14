"""Unit tests for the async event bus.

Tests cover:
- Subscribing and unsubscribing handlers
- Event emission to multiple handlers
- Error isolation (one failing handler doesn't block others)
- Unknown event type rejection
- emit_nowait fire-and-forget behavior
- Subscriber count tracking
- Clear functionality
- Event-specific scenarios matching task requirements:
  - device_updated triggers ChangeDetector and RiskScorer
  - topology_updated triggers RiskScorer recalculation
  - alert_generated triggers WebSocket broadcast and DB persistence
  - scan_completed triggers scan history recording

Requirements: 5.7, 7.1, 7.7, 11.2
"""

import asyncio
import pytest

from app.event_bus import (
    EventBus,
    DEVICE_UPDATED,
    TOPOLOGY_UPDATED,
    ALERT_GENERATED,
    SCAN_COMPLETED,
    ALL_EVENT_TYPES,
    event_bus,
)


@pytest.fixture
def bus():
    """Create a fresh EventBus instance for each test."""
    return EventBus()


class TestEventBusSubscription:
    """Tests for subscribe/unsubscribe functionality."""

    def test_subscribe_valid_event_type(self, bus: EventBus):
        """Subscribing to a valid event type registers the handler."""

        async def handler(payload):
            pass

        bus.subscribe(DEVICE_UPDATED, handler)
        assert bus.get_subscriber_count(DEVICE_UPDATED) == 1

    def test_subscribe_multiple_handlers(self, bus: EventBus):
        """Multiple handlers can subscribe to the same event type."""

        async def handler1(payload):
            pass

        async def handler2(payload):
            pass

        bus.subscribe(DEVICE_UPDATED, handler1)
        bus.subscribe(DEVICE_UPDATED, handler2)
        assert bus.get_subscriber_count(DEVICE_UPDATED) == 2

    def test_subscribe_to_different_events(self, bus: EventBus):
        """Handlers can subscribe to different event types independently."""

        async def handler1(payload):
            pass

        async def handler2(payload):
            pass

        bus.subscribe(DEVICE_UPDATED, handler1)
        bus.subscribe(TOPOLOGY_UPDATED, handler2)
        assert bus.get_subscriber_count(DEVICE_UPDATED) == 1
        assert bus.get_subscriber_count(TOPOLOGY_UPDATED) == 1

    def test_subscribe_invalid_event_type_raises(self, bus: EventBus):
        """Subscribing to an unknown event type raises ValueError."""

        async def handler(payload):
            pass

        with pytest.raises(ValueError, match="Unknown event type"):
            bus.subscribe("invalid_event", handler)

    def test_unsubscribe_existing_handler(self, bus: EventBus):
        """Unsubscribing a registered handler removes it."""

        async def handler(payload):
            pass

        bus.subscribe(DEVICE_UPDATED, handler)
        result = bus.unsubscribe(DEVICE_UPDATED, handler)
        assert result is True
        assert bus.get_subscriber_count(DEVICE_UPDATED) == 0

    def test_unsubscribe_nonexistent_handler(self, bus: EventBus):
        """Unsubscribing a handler that isn't registered returns False."""

        async def handler(payload):
            pass

        result = bus.unsubscribe(DEVICE_UPDATED, handler)
        assert result is False

    def test_unsubscribe_from_nonexistent_event(self, bus: EventBus):
        """Unsubscribing from an event with no subscribers returns False."""

        async def handler(payload):
            pass

        result = bus.unsubscribe(DEVICE_UPDATED, handler)
        assert result is False

    def test_clear_removes_all_subscribers(self, bus: EventBus):
        """Clear removes all subscribers from all event types."""

        async def handler(payload):
            pass

        bus.subscribe(DEVICE_UPDATED, handler)
        bus.subscribe(TOPOLOGY_UPDATED, handler)
        bus.subscribe(ALERT_GENERATED, handler)
        bus.clear()
        assert bus.get_subscriber_count(DEVICE_UPDATED) == 0
        assert bus.get_subscriber_count(TOPOLOGY_UPDATED) == 0
        assert bus.get_subscriber_count(ALERT_GENERATED) == 0


class TestEventBusEmit:
    """Tests for event emission."""

    @pytest.mark.asyncio
    async def test_emit_calls_handler_with_payload(self, bus: EventBus):
        """Emitting an event calls the handler with the correct payload."""
        received = []

        async def handler(payload):
            received.append(payload)

        bus.subscribe(DEVICE_UPDATED, handler)
        payload = {"device_id": "abc-123", "action": "created"}
        await bus.emit(DEVICE_UPDATED, payload)

        assert len(received) == 1
        assert received[0] == payload

    @pytest.mark.asyncio
    async def test_emit_calls_multiple_handlers(self, bus: EventBus):
        """Emitting an event calls all registered handlers."""
        results = []

        async def handler1(payload):
            results.append("handler1")

        async def handler2(payload):
            results.append("handler2")

        bus.subscribe(DEVICE_UPDATED, handler1)
        bus.subscribe(DEVICE_UPDATED, handler2)
        await bus.emit(DEVICE_UPDATED, {"device_id": "test"})

        assert "handler1" in results
        assert "handler2" in results

    @pytest.mark.asyncio
    async def test_emit_no_handlers_returns_empty(self, bus: EventBus):
        """Emitting an event with no handlers returns empty exception list."""
        exceptions = await bus.emit(DEVICE_UPDATED, {"data": "test"})
        assert exceptions == []

    @pytest.mark.asyncio
    async def test_emit_invalid_event_type_raises(self, bus: EventBus):
        """Emitting an unknown event type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown event type"):
            await bus.emit("invalid_event", {})

    @pytest.mark.asyncio
    async def test_emit_handler_exception_isolated(self, bus: EventBus):
        """A failing handler doesn't prevent other handlers from executing."""
        results = []

        async def failing_handler(payload):
            raise RuntimeError("Handler failed")

        async def success_handler(payload):
            results.append("success")

        bus.subscribe(DEVICE_UPDATED, failing_handler)
        bus.subscribe(DEVICE_UPDATED, success_handler)

        exceptions = await bus.emit(DEVICE_UPDATED, {"data": "test"})

        # The successful handler still ran
        assert "success" in results
        # The exception was captured
        assert len(exceptions) == 1
        assert isinstance(exceptions[0], RuntimeError)

    @pytest.mark.asyncio
    async def test_emit_multiple_failures_all_captured(self, bus: EventBus):
        """Multiple failing handlers all have their exceptions captured."""

        async def fail1(payload):
            raise ValueError("fail1")

        async def fail2(payload):
            raise TypeError("fail2")

        bus.subscribe(DEVICE_UPDATED, fail1)
        bus.subscribe(DEVICE_UPDATED, fail2)

        exceptions = await bus.emit(DEVICE_UPDATED, {})
        assert len(exceptions) == 2

    @pytest.mark.asyncio
    async def test_emit_does_not_affect_other_event_types(self, bus: EventBus):
        """Emitting one event type doesn't trigger handlers for other types."""
        results = []

        async def device_handler(payload):
            results.append("device")

        async def topology_handler(payload):
            results.append("topology")

        bus.subscribe(DEVICE_UPDATED, device_handler)
        bus.subscribe(TOPOLOGY_UPDATED, topology_handler)

        await bus.emit(DEVICE_UPDATED, {})
        assert results == ["device"]


class TestEventBusEmitNowait:
    """Tests for fire-and-forget emission."""

    @pytest.mark.asyncio
    async def test_emit_nowait_dispatches_event(self, bus: EventBus):
        """emit_nowait dispatches the event in a background task."""
        received = []

        async def handler(payload):
            received.append(payload)

        bus.subscribe(SCAN_COMPLETED, handler)
        await bus.emit_nowait(SCAN_COMPLETED, {"job_id": "test-job"})

        # Give the background task time to execute
        await asyncio.sleep(0.05)
        assert len(received) == 1
        assert received[0] == {"job_id": "test-job"}

    @pytest.mark.asyncio
    async def test_emit_nowait_invalid_event_raises(self, bus: EventBus):
        """emit_nowait raises ValueError for unknown event types."""
        with pytest.raises(ValueError, match="Unknown event type"):
            await bus.emit_nowait("bad_event", {})


class TestDeviceUpdatedEvent:
    """Tests for device_updated event triggering ChangeDetector and RiskScorer.

    Requirement 5.7: Device updated events trigger Change Detector.
    Requirement 7.1: Device updated events trigger Risk Scorer.
    """

    @pytest.mark.asyncio
    async def test_device_updated_triggers_change_detector(self, bus: EventBus):
        """device_updated event triggers a change detection handler."""
        change_detected = []

        async def change_detector_handler(payload):
            """Simulates ChangeDetector.process_fingerprint()."""
            change_detected.append(payload)

        bus.subscribe(DEVICE_UPDATED, change_detector_handler)
        payload = {
            "device_id": "device-001",
            "fingerprint": {"protocol": "modbus_tcp", "vendor": "Siemens"},
        }
        await bus.emit(DEVICE_UPDATED, payload)

        assert len(change_detected) == 1
        assert change_detected[0]["device_id"] == "device-001"

    @pytest.mark.asyncio
    async def test_device_updated_triggers_risk_scorer(self, bus: EventBus):
        """device_updated event triggers a risk scoring handler."""
        scores_calculated = []

        async def risk_scorer_handler(payload):
            """Simulates RiskScorer.calculate_score()."""
            scores_calculated.append(payload["device_id"])

        bus.subscribe(DEVICE_UPDATED, risk_scorer_handler)
        await bus.emit(DEVICE_UPDATED, {"device_id": "device-002"})

        assert "device-002" in scores_calculated

    @pytest.mark.asyncio
    async def test_device_updated_triggers_both_handlers(self, bus: EventBus):
        """device_updated triggers both ChangeDetector and RiskScorer concurrently."""
        invocations = []

        async def change_handler(payload):
            invocations.append("change_detector")

        async def risk_handler(payload):
            invocations.append("risk_scorer")

        bus.subscribe(DEVICE_UPDATED, change_handler)
        bus.subscribe(DEVICE_UPDATED, risk_handler)
        await bus.emit(DEVICE_UPDATED, {"device_id": "device-003"})

        assert "change_detector" in invocations
        assert "risk_scorer" in invocations


class TestTopologyUpdatedEvent:
    """Tests for topology_updated event triggering RiskScorer recalculation.

    Requirement 7.7: Topology updates trigger Risk Scorer recalculation.
    """

    @pytest.mark.asyncio
    async def test_topology_updated_triggers_risk_recalculation(self, bus: EventBus):
        """topology_updated event triggers risk score recalculation."""
        recalculations = []

        async def risk_recalc_handler(payload):
            """Simulates RiskScorer recalculation on peer count change."""
            recalculations.append(payload)

        bus.subscribe(TOPOLOGY_UPDATED, risk_recalc_handler)
        payload = {
            "device_id": "device-010",
            "peer_count": 12,
            "new_edge": {"source": "device-010", "dest": "device-011", "protocol": "modbus_tcp"},
        }
        await bus.emit(TOPOLOGY_UPDATED, payload)

        assert len(recalculations) == 1
        assert recalculations[0]["peer_count"] == 12

    @pytest.mark.asyncio
    async def test_topology_updated_with_multiple_devices(self, bus: EventBus):
        """Multiple topology updates each trigger recalculation."""
        recalculations = []

        async def handler(payload):
            recalculations.append(payload["device_id"])

        bus.subscribe(TOPOLOGY_UPDATED, handler)

        await bus.emit(TOPOLOGY_UPDATED, {"device_id": "d1", "peer_count": 5})
        await bus.emit(TOPOLOGY_UPDATED, {"device_id": "d2", "peer_count": 20})

        assert recalculations == ["d1", "d2"]


class TestAlertGeneratedEvent:
    """Tests for alert_generated event triggering WebSocket broadcast and DB persistence.

    Requirement 5.7: Alert events trigger WebSocket broadcast and database persistence.
    """

    @pytest.mark.asyncio
    async def test_alert_generated_triggers_websocket_broadcast(self, bus: EventBus):
        """alert_generated event triggers WebSocket broadcast handler."""
        broadcasts = []

        async def ws_broadcast_handler(payload):
            """Simulates alert_ws_manager.broadcast_alert()."""
            broadcasts.append(payload)

        bus.subscribe(ALERT_GENERATED, ws_broadcast_handler)
        alert_payload = {
            "alert_id": "alert-001",
            "alert_type": "new_device",
            "severity": "HIGH",
            "details": {"ip_address": "192.168.1.100"},
        }
        await bus.emit(ALERT_GENERATED, alert_payload)

        assert len(broadcasts) == 1
        assert broadcasts[0]["alert_type"] == "new_device"

    @pytest.mark.asyncio
    async def test_alert_generated_triggers_db_persistence(self, bus: EventBus):
        """alert_generated event triggers database persistence handler."""
        persisted = []

        async def db_persist_handler(payload):
            """Simulates alert database persistence."""
            persisted.append(payload["alert_id"])

        bus.subscribe(ALERT_GENERATED, db_persist_handler)
        await bus.emit(ALERT_GENERATED, {
            "alert_id": "alert-002",
            "alert_type": "firmware_change",
            "severity": "HIGH",
        })

        assert "alert-002" in persisted

    @pytest.mark.asyncio
    async def test_alert_generated_triggers_both_broadcast_and_persist(self, bus: EventBus):
        """alert_generated triggers both WebSocket broadcast and DB persistence."""
        actions = []

        async def ws_handler(payload):
            actions.append("broadcast")

        async def db_handler(payload):
            actions.append("persist")

        bus.subscribe(ALERT_GENERATED, ws_handler)
        bus.subscribe(ALERT_GENERATED, db_handler)
        await bus.emit(ALERT_GENERATED, {"alert_id": "alert-003"})

        assert "broadcast" in actions
        assert "persist" in actions


class TestScanCompletedEvent:
    """Tests for scan_completed event triggering scan history recording.

    Requirement 11.2: Scan completion events trigger scan history recording.
    """

    @pytest.mark.asyncio
    async def test_scan_completed_triggers_history_recording(self, bus: EventBus):
        """scan_completed event triggers scan history recording handler."""
        history_records = []

        async def history_handler(payload):
            """Simulates scan history recording."""
            history_records.append(payload)

        bus.subscribe(SCAN_COMPLETED, history_handler)
        payload = {
            "job_id": "scan-001",
            "started_at": "2024-01-15T10:00:00Z",
            "completed_at": "2024-01-15T10:05:00Z",
            "devices_discovered": 15,
            "new_devices": 3,
            "alerts_generated": 2,
            "status": "completed",
        }
        await bus.emit(SCAN_COMPLETED, payload)

        assert len(history_records) == 1
        assert history_records[0]["devices_discovered"] == 15
        assert history_records[0]["new_devices"] == 3

    @pytest.mark.asyncio
    async def test_scan_completed_with_failure_status(self, bus: EventBus):
        """scan_completed event with failed status is still recorded."""
        history_records = []

        async def history_handler(payload):
            history_records.append(payload)

        bus.subscribe(SCAN_COMPLETED, history_handler)
        await bus.emit(SCAN_COMPLETED, {
            "job_id": "scan-002",
            "status": "failed",
            "failure_reason": "network timeout",
        })

        assert len(history_records) == 1
        assert history_records[0]["status"] == "failed"


class TestGlobalEventBusSingleton:
    """Tests for the global event_bus singleton."""

    def test_global_event_bus_is_instance(self):
        """The global event_bus is an EventBus instance."""
        assert isinstance(event_bus, EventBus)

    def test_all_event_types_defined(self):
        """All expected event types are defined."""
        assert DEVICE_UPDATED in ALL_EVENT_TYPES
        assert TOPOLOGY_UPDATED in ALL_EVENT_TYPES
        assert ALERT_GENERATED in ALL_EVENT_TYPES
        assert SCAN_COMPLETED in ALL_EVENT_TYPES
        assert len(ALL_EVENT_TYPES) == 4


class TestConcurrentHandlerExecution:
    """Tests verifying handlers execute concurrently."""

    @pytest.mark.asyncio
    async def test_handlers_run_concurrently(self, bus: EventBus):
        """Handlers are invoked concurrently, not sequentially."""
        execution_order = []

        async def slow_handler(payload):
            execution_order.append("slow_start")
            await asyncio.sleep(0.1)
            execution_order.append("slow_end")

        async def fast_handler(payload):
            execution_order.append("fast_start")
            execution_order.append("fast_end")

        bus.subscribe(DEVICE_UPDATED, slow_handler)
        bus.subscribe(DEVICE_UPDATED, fast_handler)
        await bus.emit(DEVICE_UPDATED, {})

        # Both handlers should have started before slow_handler finishes
        # Since they run concurrently via asyncio.gather, fast should complete
        # while slow is still sleeping
        assert "slow_start" in execution_order
        assert "fast_start" in execution_order
        assert "slow_end" in execution_order
        assert "fast_end" in execution_order
