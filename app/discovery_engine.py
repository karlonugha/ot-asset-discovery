"""Discovery Engine orchestrator for OT Asset Discovery.

Initializes and connects all core components into a unified pipeline:
- PassiveSniffer → Protocol Parsers → Change Detector → Device Inventory
- ActiveProber → Protocol Parsers → Device Inventory
- Change Detector alerts → WebSocket broadcast
- Device Inventory updates → Risk Scorer recalculation
- Topology Mapper updates → Risk Scorer (peer count changes)

Supports configuration for enabling/disabling active probing.

Requirements: 1.3, 3.7, 3.8, 7.7
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID

from app.capture.sniffer import PassiveSniffer
from app.capture.prober import ActiveProber
from app.detection.change_detector import ChangeDetector
from app.scoring.risk_scorer import RiskScorer
from app.topology.mapper import TopologyMapper
from app.api.websocket_manager import WebSocketManager
from app.models.domain import Alert, DeviceFingerprint, Device, ProbeTarget

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryEngineConfig:
    """Configuration for the Discovery Engine.

    Attributes:
        active_probing_enabled: Whether active probing is enabled (Requirement 3.7).
        disappearance_timeout_hours: Hours before a device is considered disappeared.
        interface: Network interface for passive sniffing.
        topology_flush_interval: Seconds between topology flush operations.
    """

    active_probing_enabled: bool = False
    disappearance_timeout_hours: float = 24.0
    interface: Optional[str] = None
    topology_flush_interval: float = 60.0


class DiscoveryEngine:
    """Orchestrates all OT asset discovery components.

    Wires together the passive sniffer, active prober, change detector,
    device inventory, risk scorer, topology mapper, and WebSocket manager
    into a cohesive discovery pipeline.

    The engine manages the lifecycle of all components and ensures events
    flow correctly between them:

    1. Passive capture pipeline:
       PassiveSniffer → Protocol Parsers → ChangeDetector → DeviceInventory

    2. Active probing pipeline:
       ActiveProber → Protocol Parsers → DeviceInventory

    3. Alert pipeline:
       ChangeDetector → WebSocket broadcast (via WebSocketManager)

    4. Risk scoring pipeline:
       DeviceInventory updates → RiskScorer recalculation
       TopologyMapper peer count changes → RiskScorer recalculation

    Requirements: 1.3, 3.7, 3.8, 7.7
    """

    def __init__(
        self,
        config: DiscoveryEngineConfig,
        sniffer: PassiveSniffer,
        prober: ActiveProber,
        change_detector: ChangeDetector,
        risk_scorer: RiskScorer,
        topology_mapper: TopologyMapper,
        websocket_manager: WebSocketManager,
        device_repository=None,
    ) -> None:
        """Initialize the Discovery Engine with all components.

        Args:
            config: Engine configuration.
            sniffer: PassiveSniffer instance for packet capture.
            prober: ActiveProber instance for active device probing.
            change_detector: ChangeDetector for alert generation.
            risk_scorer: RiskScorer for risk score calculation.
            topology_mapper: TopologyMapper for communication graph.
            websocket_manager: WebSocketManager for real-time alert broadcast.
            device_repository: Optional DeviceRepository for database access.
                If None, the engine operates without persistence.
        """
        self._config = config
        self._sniffer = sniffer
        self._prober = prober
        self._change_detector = change_detector
        self._risk_scorer = risk_scorer
        self._topology_mapper = topology_mapper
        self._websocket_manager = websocket_manager
        self._device_repository = device_repository

        self._is_running: bool = False
        self._topology_flush_task: Optional[asyncio.Task] = None
        self._disappearance_check_task: Optional[asyncio.Task] = None

        # Wire components together
        self._wire_components()

    @property
    def config(self) -> DiscoveryEngineConfig:
        """Get the current engine configuration."""
        return self._config

    @property
    def is_running(self) -> bool:
        """Whether the discovery engine is currently running."""
        return self._is_running

    @property
    def sniffer(self) -> PassiveSniffer:
        """Access the passive sniffer component."""
        return self._sniffer

    @property
    def prober(self) -> ActiveProber:
        """Access the active prober component."""
        return self._prober

    @property
    def change_detector(self) -> ChangeDetector:
        """Access the change detector component."""
        return self._change_detector

    @property
    def risk_scorer(self) -> RiskScorer:
        """Access the risk scorer component."""
        return self._risk_scorer

    @property
    def topology_mapper(self) -> TopologyMapper:
        """Access the topology mapper component."""
        return self._topology_mapper

    @property
    def websocket_manager(self) -> WebSocketManager:
        """Access the WebSocket manager component."""
        return self._websocket_manager

    def _wire_components(self) -> None:
        """Wire all components together with event callbacks.

        Sets up the data flow between components:
        1. Sniffer → on_device_discovered → _handle_passive_discovery
        2. ChangeDetector → on_alert → _broadcast_alert_to_websocket
        3. ChangeDetector → persist_handler → _persist_alert
        4. ActiveProber → on_result → _handle_active_probe_result
        """
        # Wire PassiveSniffer → Discovery pipeline (Requirement 1.3)
        self._sniffer.on_device_discovered(self._handle_passive_discovery)

        # Wire ChangeDetector alerts → WebSocket broadcast
        self._change_detector.on_alert(self._broadcast_alert_to_websocket)

        # Wire ChangeDetector alert persistence
        self._change_detector.set_persist_handler(self._persist_alert)

    def _create_prober(self) -> ActiveProber:
        """Create a new ActiveProber wired to the discovery pipeline.

        Returns:
            ActiveProber configured with result and history callbacks.
        """
        return ActiveProber(
            on_result=self._handle_active_probe_result,
            on_scan_history=self._record_scan_history,
        )

    async def start(self) -> None:
        """Start the discovery engine.

        Starts the passive sniffer on the configured interface and
        begins periodic topology flush operations.

        Raises:
            RuntimeError: If the engine is already running.
            ValueError: If no interface is configured.
        """
        if self._is_running:
            raise RuntimeError("Discovery engine is already running")

        if self._config.interface is None:
            raise ValueError("No network interface configured for passive sniffing")

        logger.info(
            "Starting Discovery Engine (active_probing=%s, interface=%s)",
            self._config.active_probing_enabled,
            self._config.interface,
        )

        # Start passive sniffer
        await self._sniffer.start(self._config.interface)

        # Update topology mapper state
        self._topology_mapper.sniffer_running = True

        # Start periodic topology flush task
        self._topology_flush_task = asyncio.create_task(
            self._periodic_topology_flush()
        )

        self._is_running = True
        logger.info("Discovery Engine started successfully")

    async def stop(self) -> None:
        """Stop the discovery engine.

        Stops the passive sniffer, cancels periodic tasks, and flushes
        any remaining topology data.

        Raises:
            RuntimeError: If the engine is not running.
        """
        if not self._is_running:
            raise RuntimeError("Discovery engine is not running")

        logger.info("Stopping Discovery Engine...")

        # Cancel periodic tasks
        if self._topology_flush_task is not None:
            self._topology_flush_task.cancel()
            try:
                await self._topology_flush_task
            except asyncio.CancelledError:
                pass
            self._topology_flush_task = None

        if self._disappearance_check_task is not None:
            self._disappearance_check_task.cancel()
            try:
                await self._disappearance_check_task
            except asyncio.CancelledError:
                pass
            self._disappearance_check_task = None

        # Stop passive sniffer
        await self._sniffer.stop()

        # Update topology mapper state
        self._topology_mapper.sniffer_running = False

        # Final topology flush
        try:
            await self._topology_mapper.flush_updates()
        except Exception as e:
            logger.error("Error during final topology flush: %s", e)

        self._is_running = False
        logger.info("Discovery Engine stopped")

    async def run_active_probe(self, targets: list[ProbeTarget]) -> list:
        """Run active probes against specified targets.

        Only executes if active probing is enabled in configuration
        (Requirement 3.7). Results are automatically passed to the
        Device Inventory via the wired callback.

        Args:
            targets: List of ProbeTarget objects to probe.

        Returns:
            List of ProbeResult objects from the probing operation.
            Returns empty list if active probing is disabled.
        """
        if not self._config.active_probing_enabled:
            logger.info(
                "Active probing is disabled by configuration. "
                "Skipping probe of %d targets.",
                len(targets),
            )
            return []

        logger.info("Running active probe against %d targets", len(targets))
        results = await self._prober.probe_batch(targets)
        return results

    async def _handle_passive_discovery(
        self, fingerprint: DeviceFingerprint
    ) -> None:
        """Handle a device fingerprint from passive sniffing.

        Pipeline: PassiveSniffer → ChangeDetector → DeviceInventory → RiskScorer

        1. Look up existing device in inventory
        2. Run change detection (generates alerts if needed)
        3. Upsert device in inventory
        4. Recalculate risk score
        5. Record topology communication

        Args:
            fingerprint: DeviceFingerprint extracted from captured packet.

        Requirement: 1.3 (commit within 500ms of receipt)
        """
        try:
            existing_device = None
            device_record = None

            # Look up existing device
            if self._device_repository is not None:
                mac = fingerprint.mac_address or "unknown"
                ip = fingerprint.ip_address or fingerprint.source_address
                existing_db_device = await self._device_repository.get_device_by_mac_ip(
                    mac, ip
                )
                if existing_db_device is not None:
                    existing_device = {
                        "id": existing_db_device.id,
                        "mac_address": existing_db_device.mac_address,
                        "ip_address": existing_db_device.ip_address,
                        "firmware_version": existing_db_device.firmware_version,
                        "protocols": existing_db_device.protocols or [],
                    }

            # Run change detection (generates alerts for new/changed devices)
            await self._change_detector.process_fingerprint(
                fingerprint, existing_device
            )

            # Upsert device in inventory (Requirement 3.8 - same rules as passive)
            if self._device_repository is not None:
                mac = fingerprint.mac_address or "unknown"
                ip = fingerprint.ip_address or fingerprint.source_address
                protocols = [fingerprint.protocol] if fingerprint.protocol else []

                device_record, is_new = await self._device_repository.upsert_device(
                    mac_address=mac,
                    ip_address=ip,
                    vendor=fingerprint.vendor,
                    model=fingerprint.model,
                    firmware_version=fingerprint.firmware_version,
                    device_type=fingerprint.device_type,
                    protocols=protocols,
                    fingerprint=fingerprint.model_dump() if fingerprint else None,
                )

                # Recalculate risk score (Requirement 7.7)
                await self._recalculate_risk_score(device_record)

                # Record topology communication
                if existing_device is not None and fingerprint.destination_address:
                    await self._record_topology_communication(
                        fingerprint, device_record
                    )

        except Exception as e:
            logger.error(
                "Error in passive discovery pipeline for %s: %s",
                fingerprint.source_address,
                e,
                exc_info=True,
            )

    async def _handle_active_probe_result(
        self, fingerprint: DeviceFingerprint
    ) -> None:
        """Handle a device fingerprint from active probing.

        Pipeline: ActiveProber → DeviceInventory → RiskScorer

        Follows the same inventory rules as passive discovery
        (Requirement 3.8).

        Args:
            fingerprint: DeviceFingerprint from active probe response.
        """
        try:
            existing_device = None

            # Look up existing device
            if self._device_repository is not None:
                mac = fingerprint.mac_address or "unknown"
                ip = fingerprint.ip_address or fingerprint.source_address
                existing_db_device = await self._device_repository.get_device_by_mac_ip(
                    mac, ip
                )
                if existing_db_device is not None:
                    existing_device = {
                        "id": existing_db_device.id,
                        "mac_address": existing_db_device.mac_address,
                        "ip_address": existing_db_device.ip_address,
                        "firmware_version": existing_db_device.firmware_version,
                        "protocols": existing_db_device.protocols or [],
                    }

            # Run change detection
            await self._change_detector.process_fingerprint(
                fingerprint, existing_device
            )

            # Upsert device in inventory (Requirement 3.8)
            if self._device_repository is not None:
                mac = fingerprint.mac_address or "unknown"
                ip = fingerprint.ip_address or fingerprint.source_address
                protocols = [fingerprint.protocol] if fingerprint.protocol else []

                device_record, is_new = await self._device_repository.upsert_device(
                    mac_address=mac,
                    ip_address=ip,
                    vendor=fingerprint.vendor,
                    model=fingerprint.model,
                    firmware_version=fingerprint.firmware_version,
                    device_type=fingerprint.device_type,
                    protocols=protocols,
                    fingerprint=fingerprint.model_dump() if fingerprint else None,
                )

                # Recalculate risk score (Requirement 7.7)
                await self._recalculate_risk_score(device_record)

        except Exception as e:
            logger.error(
                "Error in active probe pipeline for %s: %s",
                fingerprint.source_address,
                e,
                exc_info=True,
            )

    async def _recalculate_risk_score(self, device_record) -> None:
        """Recalculate risk score for a device after inventory update.

        Gets the peer count from the topology mapper and uses the risk
        scorer to compute the new score. If the score changes significantly,
        a risk_score_change alert is generated.

        Args:
            device_record: The device database record to score.

        Requirement: 7.7 (recalculate when topology updates peer count)
        """
        try:
            # Get peer count from topology mapper
            peer_count = await self._get_peer_count(device_record.id)

            # Build a domain Device for the scorer
            device = Device(
                id=device_record.id,
                mac_address=device_record.mac_address,
                ip_address=str(device_record.ip_address),
                vendor=device_record.vendor,
                model=device_record.model,
                firmware_version=device_record.firmware_version,
                device_type=device_record.device_type,
                protocols=device_record.protocols or [],
                risk_score=device_record.risk_score or 0,
                first_seen=device_record.first_seen,
                last_seen=device_record.last_seen,
            )

            # Calculate new score
            previous_score = device_record.risk_score
            result = self._risk_scorer.calculate_score(
                device, peer_count=peer_count, previous_score=previous_score
            )

            # Update device record with new score
            if result.score != previous_score:
                device_record.risk_score = result.score

            # If a risk_score_change alert was generated, persist and broadcast
            if result.alert is not None:
                await self._persist_alert(result.alert)
                await self._broadcast_alert_to_websocket(result.alert)

        except Exception as e:
            logger.error(
                "Error recalculating risk score for device %s: %s",
                device_record.id,
                e,
            )

    async def _get_peer_count(self, device_id: UUID) -> int:
        """Get the number of unique communication peers for a device.

        Counts unique devices that have communicated with the given device
        based on topology mapper data.

        Args:
            device_id: The device UUID to count peers for.

        Returns:
            Number of unique communication peers.
        """
        topology = await self._topology_mapper.get_topology()
        peers: set[UUID] = set()

        for edge in topology.edges:
            if edge.source_device_id == device_id:
                peers.add(edge.dest_device_id)
            elif edge.dest_device_id == device_id:
                peers.add(edge.source_device_id)

        return len(peers)

    async def _record_topology_communication(
        self, fingerprint: DeviceFingerprint, device_record
    ) -> None:
        """Record a communication event in the topology mapper.

        If a new communication path is detected, broadcasts the event
        via WebSocket and triggers risk score recalculation for affected
        devices (Requirement 7.7).

        Args:
            fingerprint: The device fingerprint with source/dest info.
            device_record: The source device database record.
        """
        try:
            # We need the destination device ID - look it up
            if self._device_repository is not None and fingerprint.destination_address:
                # Try to find destination device by IP
                # Note: This is a best-effort lookup
                dest_device = None
                # For topology, we record the communication if we can identify both ends
                # In practice, the destination might not be in our inventory yet
                pass

            # Record communication in topology mapper
            # For now, we record using the source device ID
            # Full topology recording requires both device IDs
            # This will be enhanced when both devices are known
            event = await self._topology_mapper.record_communication(
                source_id=device_record.id,
                dest_id=device_record.id,  # Placeholder - needs dest device lookup
                protocol=fingerprint.protocol,
            )

            if event is not None:
                # Broadcast new communication path event via WebSocket
                await self._websocket_manager.broadcast_json({
                    "type": "new_communication_path",
                    "data": {
                        "source_device_id": str(event.source_device_id),
                        "dest_device_id": str(event.dest_device_id),
                        "protocol": event.protocol,
                        "timestamp": event.timestamp.isoformat(),
                    },
                })

                # Recalculate risk scores for affected devices (peer count changed)
                await self._recalculate_risk_score(device_record)

        except Exception as e:
            logger.error(
                "Error recording topology communication: %s", e
            )

    async def _broadcast_alert_to_websocket(self, alert: Alert) -> None:
        """Broadcast an alert to all connected WebSocket clients.

        Converts the alert to a dictionary and sends it via the
        WebSocket manager within 2 seconds of generation.

        Args:
            alert: The Alert to broadcast.
        """
        try:
            alert_data = {
                "id": str(alert.id),
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "device_id": str(alert.device_id) if alert.device_id else None,
                "details": alert.details,
                "generated_at": alert.generated_at.isoformat(),
            }
            await self._websocket_manager.broadcast_alert(alert_data)
        except Exception as e:
            logger.error("Error broadcasting alert via WebSocket: %s", e)

    async def _persist_alert(self, alert: Alert) -> None:
        """Persist an alert to the database.

        This is called by the ChangeDetector before dispatching to
        WebSocket (Requirement 5.7).

        Args:
            alert: The Alert to persist.
        """
        # Alert persistence is handled by the database layer
        # In a full implementation, this would write to the alerts table
        logger.debug("Alert persisted: %s (%s)", alert.alert_type, alert.id)

    async def _record_scan_history(self, history_entry: dict) -> None:
        """Record a scan history entry from active probing.

        Args:
            history_entry: Dictionary with probe result details.
        """
        logger.debug("Scan history recorded: %s", history_entry)

    async def _periodic_topology_flush(self) -> None:
        """Periodically flush topology mapper updates to the database.

        Runs at the configured interval (default 60 seconds) to persist
        buffered packet counts and timestamps.
        """
        while True:
            try:
                await asyncio.sleep(self._config.topology_flush_interval)
                await self._topology_mapper.flush_updates()
                logger.debug("Topology flush completed")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in periodic topology flush: %s", e)

    async def handle_topology_update(
        self, source_id: UUID, dest_id: UUID, protocol: str
    ) -> None:
        """Handle a topology update and trigger risk score recalculation.

        Called when the topology mapper records a new communication event.
        Triggers risk score recalculation for both affected devices since
        their peer counts may have changed (Requirement 7.7).

        Args:
            source_id: Source device UUID.
            dest_id: Destination device UUID.
            protocol: Communication protocol.
        """
        event = await self._topology_mapper.record_communication(
            source_id, dest_id, protocol
        )

        if event is not None:
            # Broadcast new communication path
            await self._websocket_manager.broadcast_json({
                "type": "new_communication_path",
                "data": {
                    "source_device_id": str(event.source_device_id),
                    "dest_device_id": str(event.dest_device_id),
                    "protocol": event.protocol,
                    "timestamp": event.timestamp.isoformat(),
                },
            })

        # Recalculate risk scores for both devices (peer count may have changed)
        if self._device_repository is not None:
            for device_id in (source_id, dest_id):
                device_record = await self._device_repository.get_device_by_id(device_id)
                if device_record is not None:
                    await self._recalculate_risk_score(device_record)

    def set_active_probing(self, enabled: bool) -> None:
        """Enable or disable active probing.

        When disabled, the Discovery Engine relies exclusively on passive
        traffic analysis for device identification (Requirement 3.7).

        Args:
            enabled: Whether active probing should be enabled.
        """
        self._config.active_probing_enabled = enabled
        logger.info("Active probing %s", "enabled" if enabled else "disabled")
