"""Topology Mapper for recording and querying device communication relationships.

Maintains a graph of observed device communication relationships from
passive traffic capture. Records unique (source_device_id, dest_device_id,
protocol) triples with cumulative packet counts and last-seen timestamps.

Generates "new_communication_path" events for first observations and
supports periodic flushing of buffered updates to the database.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import Device, TopologyEdge as TopologyEdgeDB
from app.models.domain import TopologyEdge, TopologyGraph, TopologyNode

logger = logging.getLogger(__name__)

# Maximum flush interval in seconds (Requirement 6.4)
MAX_FLUSH_INTERVAL_SECONDS = 60


@dataclass
class NewCommunicationEvent:
    """Event generated when a new communication path is first observed.

    Broadcast to WebSocket clients as a message of type 'new_communication_path'.
    """

    source_device_id: UUID
    dest_device_id: UUID
    protocol: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class _BufferedEdge:
    """Internal buffer entry for an observed communication triple.

    Tracks the cumulative packet count and last-seen timestamp for a
    (source, dest, protocol) triple since the last flush.
    """

    source_device_id: UUID
    dest_device_id: UUID
    protocol: str
    packet_count: int = 0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TopologyMapper:
    """Maintains a graph of observed device communication relationships.

    Records each unique source-destination device pair identified by
    source device id, destination device id, and protocol, maintaining
    a cumulative packet count and a last-seen timestamp for each pair.

    The mapper buffers updates in memory and periodically flushes them
    to the database at intervals no greater than 60 seconds (Requirement 6.4).

    Attributes:
        sniffer_running: Whether the passive sniffer is currently active.
    """

    def __init__(self, session_factory=None) -> None:
        """Initialize the TopologyMapper.

        Args:
            session_factory: Async session factory for database access.
                If None, the mapper operates in memory-only mode.
        """
        self._session_factory = session_factory
        # In-memory buffer: key is (source_id, dest_id, protocol)
        self._buffer: dict[tuple[UUID, UUID, str], _BufferedEdge] = {}
        self._buffer_lock: asyncio.Lock = asyncio.Lock()
        # Set of triples observed since sniffer start (for new_communication_path events)
        self._observed_triples: set[tuple[UUID, UUID, str]] = set()
        self._observed_lock: asyncio.Lock = asyncio.Lock()
        # Sniffer state tracking
        self._sniffer_running: bool = False
        self._last_flush: Optional[datetime] = None
        self._last_updated: Optional[datetime] = None

    @property
    def sniffer_running(self) -> bool:
        """Whether the passive sniffer is currently active."""
        return self._sniffer_running

    @sniffer_running.setter
    def sniffer_running(self, value: bool) -> None:
        """Set the sniffer running state.

        When set to True (sniffer started), resets the observed triples
        so that new_communication_path events fire again for all triples.
        """
        if value and not self._sniffer_running:
            # Sniffer is starting - reset observed triples (Requirement 6.3)
            self._observed_triples = set()
            logger.info("Topology mapper: sniffer started, resetting observed triples")
        self._sniffer_running = value

    async def record_communication(
        self, source_id: UUID, dest_id: UUID, protocol: str
    ) -> Optional[NewCommunicationEvent]:
        """Record a communication event between two devices.

        Updates the in-memory buffer with the new observation. If this is
        the first time this (source, dest, protocol) triple has been observed
        since the sniffer was last started, generates a NewCommunicationEvent.

        Args:
            source_id: Source device UUID.
            dest_id: Destination device UUID.
            protocol: Protocol name (e.g., "modbus_tcp", "ethernetip").

        Returns:
            NewCommunicationEvent if this is a new communication path,
            None otherwise.
        """
        triple = (source_id, dest_id, protocol)
        now = datetime.now(timezone.utc)
        event: Optional[NewCommunicationEvent] = None

        # Check if this is a new communication path (Requirement 6.3)
        async with self._observed_lock:
            is_new = triple not in self._observed_triples
            if is_new:
                self._observed_triples.add(triple)

        # Update the buffer (Requirement 6.1)
        async with self._buffer_lock:
            if triple in self._buffer:
                edge = self._buffer[triple]
                edge.packet_count += 1
                edge.last_seen = now
            else:
                self._buffer[triple] = _BufferedEdge(
                    source_device_id=source_id,
                    dest_device_id=dest_id,
                    protocol=protocol,
                    packet_count=1,
                    last_seen=now,
                    first_seen=now,
                )

        # Generate event for first observation (Requirement 6.3)
        if is_new:
            event = NewCommunicationEvent(
                source_device_id=source_id,
                dest_device_id=dest_id,
                protocol=protocol,
                timestamp=now,
            )
            logger.info(
                "New communication path: %s -> %s via %s",
                source_id,
                dest_id,
                protocol,
            )

        self._last_updated = now
        return event

    async def flush_updates(self) -> None:
        """Persist buffered packet counts and timestamps to the database.

        Called periodically at intervals no greater than 60 seconds
        (Requirement 6.4). For each buffered triple, either creates a new
        topology_edges record or updates the existing one with the
        accumulated packet count and latest timestamp.

        If no session factory is configured, this is a no-op (memory-only mode).
        """
        if self._session_factory is None:
            # Memory-only mode - clear buffer and mark as flushed
            async with self._buffer_lock:
                self._buffer.clear()
            self._last_flush = datetime.now(timezone.utc)
            return

        async with self._buffer_lock:
            if not self._buffer:
                self._last_flush = datetime.now(timezone.utc)
                return

            # Snapshot and clear the buffer
            edges_to_flush = dict(self._buffer)
            self._buffer.clear()

        # Persist to database
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    for triple, buffered_edge in edges_to_flush.items():
                        await self._persist_edge(session, buffered_edge)

            self._last_flush = datetime.now(timezone.utc)
            logger.info(
                "Flushed %d topology edge updates to database",
                len(edges_to_flush),
            )
        except Exception as e:
            # On failure, put edges back into the buffer so they aren't lost
            logger.error("Failed to flush topology updates: %s", e)
            async with self._buffer_lock:
                for triple, buffered_edge in edges_to_flush.items():
                    if triple in self._buffer:
                        # Merge with any new observations since the flush started
                        existing = self._buffer[triple]
                        existing.packet_count += buffered_edge.packet_count
                        if buffered_edge.first_seen < existing.first_seen:
                            existing.first_seen = buffered_edge.first_seen
                    else:
                        self._buffer[triple] = buffered_edge
            raise

    async def _persist_edge(
        self, session: AsyncSession, buffered_edge: _BufferedEdge
    ) -> None:
        """Persist a single buffered edge to the database.

        If the edge already exists, updates packet_count and last_seen.
        If it doesn't exist, creates a new record.

        Args:
            session: Active database session.
            buffered_edge: The buffered edge data to persist.
        """
        # Look for existing edge
        stmt = select(TopologyEdgeDB).where(
            TopologyEdgeDB.source_device_id == buffered_edge.source_device_id,
            TopologyEdgeDB.dest_device_id == buffered_edge.dest_device_id,
            TopologyEdgeDB.protocol == buffered_edge.protocol,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing is not None:
            # Update existing edge - add to cumulative packet count
            existing.packet_count += buffered_edge.packet_count
            if buffered_edge.last_seen > existing.last_seen:
                existing.last_seen = buffered_edge.last_seen
        else:
            # Create new edge
            new_edge = TopologyEdgeDB(
                source_device_id=buffered_edge.source_device_id,
                dest_device_id=buffered_edge.dest_device_id,
                protocol=buffered_edge.protocol,
                packet_count=buffered_edge.packet_count,
                first_seen=buffered_edge.first_seen,
                last_seen=buffered_edge.last_seen,
            )
            session.add(new_edge)

    async def get_topology(self) -> TopologyGraph:
        """Return the current network topology as nodes and edges.

        If the sniffer is not running, sets the stale flag to True and
        includes the last_updated timestamp (Requirement 6.5).

        If a session factory is configured, queries the database for
        persisted topology data. Also includes any buffered (not yet flushed)
        edges in the response.

        Returns:
            TopologyGraph with nodes, edges, stale flag, and last_updated.
        """
        nodes: list[TopologyNode] = []
        edges: list[TopologyEdge] = []
        device_ids: set[UUID] = set()

        # Get persisted edges from database
        if self._session_factory is not None:
            async with self._session_factory() as session:
                # Query all topology edges
                edge_stmt = select(TopologyEdgeDB)
                edge_result = await session.execute(edge_stmt)
                db_edges = edge_result.scalars().all()

                for db_edge in db_edges:
                    edges.append(TopologyEdge(
                        source_device_id=db_edge.source_device_id,
                        dest_device_id=db_edge.dest_device_id,
                        protocol=db_edge.protocol,
                        packet_count=db_edge.packet_count,
                        last_seen=db_edge.last_seen,
                    ))
                    device_ids.add(db_edge.source_device_id)
                    device_ids.add(db_edge.dest_device_id)

                # Also include buffered edges not yet flushed
                async with self._buffer_lock:
                    for triple, buffered_edge in self._buffer.items():
                        # Check if this edge is already in the persisted set
                        existing_edge = next(
                            (e for e in edges
                             if e.source_device_id == buffered_edge.source_device_id
                             and e.dest_device_id == buffered_edge.dest_device_id
                             and e.protocol == buffered_edge.protocol),
                            None,
                        )
                        if existing_edge is not None:
                            # Merge buffered counts into the response
                            existing_edge.packet_count += buffered_edge.packet_count
                            if buffered_edge.last_seen > existing_edge.last_seen:
                                existing_edge.last_seen = buffered_edge.last_seen
                        else:
                            edges.append(TopologyEdge(
                                source_device_id=buffered_edge.source_device_id,
                                dest_device_id=buffered_edge.dest_device_id,
                                protocol=buffered_edge.protocol,
                                packet_count=buffered_edge.packet_count,
                                last_seen=buffered_edge.last_seen,
                            ))
                            device_ids.add(buffered_edge.source_device_id)
                            device_ids.add(buffered_edge.dest_device_id)

                # Fetch device info for nodes
                if device_ids:
                    device_stmt = select(Device).where(Device.id.in_(list(device_ids)))
                    device_result = await session.execute(device_stmt)
                    devices = device_result.scalars().all()

                    for device in devices:
                        nodes.append(TopologyNode(
                            device_id=device.id,
                            name=f"{device.ip_address} - {device.vendor}" if device.vendor else str(device.ip_address),
                            ip_address=str(device.ip_address),
                            device_type=device.device_type,
                        ))
        else:
            # Memory-only mode - return buffered edges
            async with self._buffer_lock:
                for triple, buffered_edge in self._buffer.items():
                    edges.append(TopologyEdge(
                        source_device_id=buffered_edge.source_device_id,
                        dest_device_id=buffered_edge.dest_device_id,
                        protocol=buffered_edge.protocol,
                        packet_count=buffered_edge.packet_count,
                        last_seen=buffered_edge.last_seen,
                    ))
                    device_ids.add(buffered_edge.source_device_id)
                    device_ids.add(buffered_edge.dest_device_id)

            # In memory-only mode, create minimal nodes from device IDs
            for device_id in device_ids:
                nodes.append(TopologyNode(
                    device_id=device_id,
                    name=str(device_id),
                    ip_address="unknown",
                    device_type=None,
                ))

        # Set stale flag when sniffer is not running (Requirement 6.5)
        stale = not self._sniffer_running

        return TopologyGraph(
            nodes=nodes,
            edges=edges,
            stale=stale,
            last_updated=self._last_updated,
        )

    def get_buffered_count(self) -> int:
        """Return the number of edges currently buffered (not yet flushed).

        Useful for monitoring and testing.
        """
        return len(self._buffer)

    def get_observed_triple_count(self) -> int:
        """Return the number of unique triples observed since sniffer start.

        Useful for monitoring and testing.
        """
        return len(self._observed_triples)
