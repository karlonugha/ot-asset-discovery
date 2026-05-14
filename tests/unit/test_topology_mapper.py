"""Unit tests for the TopologyMapper class.

Tests cover:
- Recording unique communication triples with cumulative packet counts
- Generating new_communication_path events for first observations
- flush_updates() persisting buffered counts
- get_topology() returning nodes and edges with stale flag
- Sniffer state reset behavior

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.topology.mapper import TopologyMapper, NewCommunicationEvent


@pytest.fixture
def mapper():
    """Create a TopologyMapper in memory-only mode for testing."""
    m = TopologyMapper(session_factory=None)
    m.sniffer_running = True
    return m


class TestRecordCommunication:
    """Tests for recording communication triples (Requirement 6.1)."""

    async def test_records_new_triple(self, mapper):
        """First observation of a triple should be recorded with count 1."""
        src = uuid4()
        dst = uuid4()
        protocol = "modbus_tcp"

        await mapper.record_communication(src, dst, protocol)

        assert mapper.get_buffered_count() == 1

    async def test_increments_packet_count_on_repeat(self, mapper):
        """Repeated observations of the same triple increment packet count."""
        src = uuid4()
        dst = uuid4()
        protocol = "modbus_tcp"

        await mapper.record_communication(src, dst, protocol)
        await mapper.record_communication(src, dst, protocol)
        await mapper.record_communication(src, dst, protocol)

        # Check the buffer directly
        triple = (src, dst, protocol)
        assert mapper._buffer[triple].packet_count == 3

    async def test_different_triples_tracked_separately(self, mapper):
        """Different (src, dst, protocol) triples are tracked independently."""
        src1 = uuid4()
        src2 = uuid4()
        dst = uuid4()
        protocol = "modbus_tcp"

        await mapper.record_communication(src1, dst, protocol)
        await mapper.record_communication(src2, dst, protocol)

        assert mapper.get_buffered_count() == 2

    async def test_same_devices_different_protocol_tracked_separately(self, mapper):
        """Same device pair with different protocols are separate triples."""
        src = uuid4()
        dst = uuid4()

        await mapper.record_communication(src, dst, "modbus_tcp")
        await mapper.record_communication(src, dst, "ethernetip")

        assert mapper.get_buffered_count() == 2

    async def test_last_seen_updated_on_repeat(self, mapper):
        """last_seen timestamp is updated on each observation."""
        src = uuid4()
        dst = uuid4()
        protocol = "s7comm"

        await mapper.record_communication(src, dst, protocol)
        first_seen = mapper._buffer[(src, dst, protocol)].last_seen

        # Small delay to ensure timestamp difference
        await asyncio.sleep(0.01)
        await mapper.record_communication(src, dst, protocol)
        second_seen = mapper._buffer[(src, dst, protocol)].last_seen

        assert second_seen >= first_seen


class TestNewCommunicationPathEvent:
    """Tests for new_communication_path event generation (Requirement 6.3)."""

    async def test_first_observation_generates_event(self, mapper):
        """First observation of a triple generates a NewCommunicationEvent."""
        src = uuid4()
        dst = uuid4()
        protocol = "modbus_tcp"

        event = await mapper.record_communication(src, dst, protocol)

        assert event is not None
        assert isinstance(event, NewCommunicationEvent)
        assert event.source_device_id == src
        assert event.dest_device_id == dst
        assert event.protocol == protocol

    async def test_repeat_observation_no_event(self, mapper):
        """Repeated observation of same triple does NOT generate an event."""
        src = uuid4()
        dst = uuid4()
        protocol = "modbus_tcp"

        # First observation - generates event
        event1 = await mapper.record_communication(src, dst, protocol)
        assert event1 is not None

        # Second observation - no event
        event2 = await mapper.record_communication(src, dst, protocol)
        assert event2 is None

    async def test_different_triple_generates_event(self, mapper):
        """A different triple generates its own event."""
        src1 = uuid4()
        src2 = uuid4()
        dst = uuid4()
        protocol = "modbus_tcp"

        event1 = await mapper.record_communication(src1, dst, protocol)
        event2 = await mapper.record_communication(src2, dst, protocol)

        assert event1 is not None
        assert event2 is not None

    async def test_sniffer_restart_resets_observed_triples(self, mapper):
        """Restarting the sniffer resets observed triples, allowing new events."""
        src = uuid4()
        dst = uuid4()
        protocol = "modbus_tcp"

        # First observation
        event1 = await mapper.record_communication(src, dst, protocol)
        assert event1 is not None

        # Repeat - no event
        event2 = await mapper.record_communication(src, dst, protocol)
        assert event2 is None

        # Simulate sniffer restart
        mapper.sniffer_running = False
        mapper.sniffer_running = True

        # Same triple now generates event again
        event3 = await mapper.record_communication(src, dst, protocol)
        assert event3 is not None

    async def test_event_has_timestamp(self, mapper):
        """Generated events include a timestamp."""
        src = uuid4()
        dst = uuid4()

        event = await mapper.record_communication(src, dst, "dnp3")

        assert event is not None
        assert event.timestamp is not None
        assert isinstance(event.timestamp, datetime)


class TestFlushUpdates:
    """Tests for flush_updates() (Requirement 6.4)."""

    async def test_flush_clears_buffer(self, mapper):
        """flush_updates() clears the in-memory buffer."""
        src = uuid4()
        dst = uuid4()

        await mapper.record_communication(src, dst, "modbus_tcp")
        assert mapper.get_buffered_count() == 1

        await mapper.flush_updates()
        assert mapper.get_buffered_count() == 0

    async def test_flush_empty_buffer_succeeds(self, mapper):
        """flush_updates() with empty buffer is a no-op."""
        await mapper.flush_updates()
        assert mapper.get_buffered_count() == 0

    async def test_flush_updates_last_flush_timestamp(self, mapper):
        """flush_updates() updates the last_flush timestamp."""
        assert mapper._last_flush is None

        await mapper.flush_updates()

        assert mapper._last_flush is not None
        assert isinstance(mapper._last_flush, datetime)

    async def test_flush_multiple_edges(self, mapper):
        """flush_updates() handles multiple buffered edges."""
        for i in range(5):
            await mapper.record_communication(uuid4(), uuid4(), "modbus_tcp")

        assert mapper.get_buffered_count() == 5

        await mapper.flush_updates()
        assert mapper.get_buffered_count() == 0


class TestGetTopology:
    """Tests for get_topology() (Requirements 6.2, 6.5)."""

    async def test_empty_topology(self, mapper):
        """get_topology() returns empty graph when no communications recorded."""
        graph = await mapper.get_topology()

        assert graph.nodes == []
        assert graph.edges == []

    async def test_topology_includes_buffered_edges(self, mapper):
        """get_topology() includes edges from the buffer."""
        src = uuid4()
        dst = uuid4()

        await mapper.record_communication(src, dst, "modbus_tcp")
        await mapper.record_communication(src, dst, "modbus_tcp")

        graph = await mapper.get_topology()

        assert len(graph.edges) == 1
        edge = graph.edges[0]
        assert edge.source_device_id == src
        assert edge.dest_device_id == dst
        assert edge.protocol == "modbus_tcp"
        assert edge.packet_count == 2

    async def test_topology_includes_nodes_for_all_devices(self, mapper):
        """get_topology() includes a node for each device in edges."""
        src = uuid4()
        dst = uuid4()

        await mapper.record_communication(src, dst, "ethernetip")

        graph = await mapper.get_topology()

        assert len(graph.nodes) == 2
        node_ids = {n.device_id for n in graph.nodes}
        assert src in node_ids
        assert dst in node_ids

    async def test_stale_flag_when_sniffer_not_running(self, mapper):
        """get_topology() sets stale=True when sniffer is not running (Req 6.5)."""
        mapper.sniffer_running = False

        graph = await mapper.get_topology()

        assert graph.stale is True

    async def test_not_stale_when_sniffer_running(self, mapper):
        """get_topology() sets stale=False when sniffer is running."""
        mapper.sniffer_running = True

        graph = await mapper.get_topology()

        assert graph.stale is False

    async def test_last_updated_reflects_latest_communication(self, mapper):
        """get_topology() includes last_updated timestamp."""
        src = uuid4()
        dst = uuid4()

        await mapper.record_communication(src, dst, "modbus_tcp")

        graph = await mapper.get_topology()

        assert graph.last_updated is not None

    async def test_topology_multiple_edges(self, mapper):
        """get_topology() returns all unique edges."""
        src1 = uuid4()
        src2 = uuid4()
        dst = uuid4()

        await mapper.record_communication(src1, dst, "modbus_tcp")
        await mapper.record_communication(src2, dst, "s7comm")
        await mapper.record_communication(src1, dst, "ethernetip")

        graph = await mapper.get_topology()

        assert len(graph.edges) == 3

    async def test_topology_deduplicates_nodes(self, mapper):
        """get_topology() does not duplicate nodes for devices in multiple edges."""
        src = uuid4()
        dst1 = uuid4()
        dst2 = uuid4()

        await mapper.record_communication(src, dst1, "modbus_tcp")
        await mapper.record_communication(src, dst2, "modbus_tcp")

        graph = await mapper.get_topology()

        # src appears in two edges but should only have one node
        node_ids = [n.device_id for n in graph.nodes]
        assert node_ids.count(src) == 1
        assert len(graph.nodes) == 3  # src, dst1, dst2


class TestSnifferStateManagement:
    """Tests for sniffer state tracking."""

    async def test_initial_sniffer_state_is_not_running(self):
        """TopologyMapper starts with sniffer_running=False."""
        mapper = TopologyMapper(session_factory=None)
        assert mapper.sniffer_running is False

    async def test_setting_sniffer_running_true_resets_triples(self):
        """Setting sniffer_running to True resets observed triples."""
        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        src = uuid4()
        dst = uuid4()
        await mapper.record_communication(src, dst, "modbus_tcp")
        assert mapper.get_observed_triple_count() == 1

        # Stop and restart
        mapper.sniffer_running = False
        mapper.sniffer_running = True

        assert mapper.get_observed_triple_count() == 0

    async def test_setting_sniffer_running_false_does_not_reset(self):
        """Setting sniffer_running to False does not reset observed triples."""
        mapper = TopologyMapper(session_factory=None)
        mapper.sniffer_running = True

        src = uuid4()
        dst = uuid4()
        await mapper.record_communication(src, dst, "modbus_tcp")
        assert mapper.get_observed_triple_count() == 1

        mapper.sniffer_running = False
        assert mapper.get_observed_triple_count() == 1
