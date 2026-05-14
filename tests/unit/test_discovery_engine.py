"""Unit tests for the Discovery Engine orchestrator.

Tests the wiring and orchestration of all components:
- PassiveSniffer → Protocol Parsers → Change Detector → Device Inventory
- ActiveProber → Protocol Parsers → Device Inventory
- Change Detector alerts → WebSocket broadcast
- Device Inventory updates → Risk Scorer recalculation
- Topology Mapper updates → Risk Scorer (peer count changes)
- Configuration for active probing enable/disable
"""

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.discovery_engine import DiscoveryEngine, DiscoveryEngineConfig
from app.capture.sniffer import PassiveSniffer
from app.capture.prober import ActiveProber
from app.detection.change_detector import ChangeDetector
from app.scoring.risk_scorer import RiskScorer, RiskScoreResult
from app.topology.mapper import TopologyMapper
from app.api.websocket_manager import WebSocketManager
from app.models.domain import (
    Alert,
    Device,
    DeviceFingerprint,
    ProbeTarget,
    TopologyGraph,
    TopologyEdge,
    TopologyNode,
)


@pytest.fixture
def config():
    """Create a default engine configuration."""
    return DiscoveryEngineConfig(
        active_probing_enabled=False,
        disappearance_timeout_hours=24.0,
        interface="eth0",
        topology_flush_interval=60.0,
    )


@pytest.fixture
def mock_sniffer():
    """Create a mock PassiveSniffer."""
    sniffer = MagicMock(spec=PassiveSniffer)
    sniffer.is_running = False
    sniffer.on_device_discovered = MagicMock()
    sniffer.on_packet = MagicMock()
    sniffer.start = AsyncMock()
    sniffer.stop = AsyncMock()
    return sniffer


@pytest.fixture
def mock_prober():
    """Create a mock ActiveProber."""
    prober = MagicMock(spec=ActiveProber)
    prober.probe_batch = AsyncMock(return_value=[])
    prober.probe_device = AsyncMock()
    return prober


@pytest.fixture
def change_detector():
    """Create a real ChangeDetector instance."""
    return ChangeDetector(disappearance_timeout_hours=24.0)


@pytest.fixture
def risk_scorer():
    """Create a real RiskScorer instance."""
    return RiskScorer()


@pytest.fixture
def topology_mapper():
    """Create a real TopologyMapper instance (memory-only mode)."""
    return TopologyMapper(session_factory=None)


@pytest.fixture
def mock_websocket_manager():
    """Create a mock WebSocketManager."""
    ws_manager = MagicMock(spec=WebSocketManager)
    ws_manager.broadcast_alert = AsyncMock()
    ws_manager.broadcast_json = AsyncMock()
    ws_manager.active_connections = 0
    return ws_manager


@pytest.fixture
def mock_device_repository():
    """Create a mock device repository."""
    repo = MagicMock()
    repo.get_device_by_mac_ip = AsyncMock(return_value=None)
    repo.get_device_by_id = AsyncMock(return_value=None)
    repo.upsert_device = AsyncMock()
    return repo


@pytest.fixture
def engine(
    config,
    mock_sniffer,
    mock_prober,
    change_detector,
    risk_scorer,
    topology_mapper,
    mock_websocket_manager,
    mock_device_repository,
):
    """Create a DiscoveryEngine with all mocked/real components."""
    return DiscoveryEngine(
        config=config,
        sniffer=mock_sniffer,
        prober=mock_prober,
        change_detector=change_detector,
        risk_scorer=risk_scorer,
        topology_mapper=topology_mapper,
        websocket_manager=mock_websocket_manager,
        device_repository=mock_device_repository,
    )


class TestDiscoveryEngineInit:
    """Tests for Discovery Engine initialization and wiring."""

    def test_engine_initializes_with_all_components(self, engine):
        """Engine should initialize with all components accessible."""
        assert engine.sniffer is not None
        assert engine.prober is not None
        assert engine.change_detector is not None
        assert engine.risk_scorer is not None
        assert engine.topology_mapper is not None
        assert engine.websocket_manager is not None

    def test_engine_not_running_initially(self, engine):
        """Engine should not be running after initialization."""
        assert engine.is_running is False

    def test_sniffer_on_device_discovered_wired(self, engine, mock_sniffer):
        """Sniffer's on_device_discovered callback should be registered."""
        mock_sniffer.on_device_discovered.assert_called_once()

    def test_change_detector_alert_callback_wired(self, engine, change_detector):
        """ChangeDetector should have an alert callback registered."""
        assert len(change_detector._alert_callbacks) > 0

    def test_change_detector_persist_handler_wired(self, engine, change_detector):
        """ChangeDetector should have a persist handler set."""
        assert change_detector._persist_alert is not None

    def test_config_accessible(self, engine, config):
        """Engine configuration should be accessible."""
        assert engine.config == config
        assert engine.config.active_probing_enabled is False
        assert engine.config.interface == "eth0"


class TestDiscoveryEngineStartStop:
    """Tests for engine start/stop lifecycle."""

    async def test_start_calls_sniffer_start(self, engine, mock_sniffer):
        """Starting the engine should start the passive sniffer."""
        await engine.start()
        mock_sniffer.start.assert_called_once_with("eth0")
        assert engine.is_running is True

    async def test_start_sets_topology_mapper_running(self, engine, topology_mapper):
        """Starting the engine should set topology mapper sniffer_running."""
        await engine.start()
        assert topology_mapper.sniffer_running is True

    async def test_start_raises_if_already_running(self, engine):
        """Starting an already-running engine should raise RuntimeError."""
        await engine.start()
        with pytest.raises(RuntimeError, match="already running"):
            await engine.start()

    async def test_start_raises_if_no_interface(
        self, mock_sniffer, mock_prober, change_detector,
        risk_scorer, topology_mapper, mock_websocket_manager,
        mock_device_repository,
    ):
        """Starting without a configured interface should raise ValueError."""
        config = DiscoveryEngineConfig(interface=None)
        engine = DiscoveryEngine(
            config=config,
            sniffer=mock_sniffer,
            prober=mock_prober,
            change_detector=change_detector,
            risk_scorer=risk_scorer,
            topology_mapper=topology_mapper,
            websocket_manager=mock_websocket_manager,
            device_repository=mock_device_repository,
        )
        with pytest.raises(ValueError, match="No network interface"):
            await engine.start()

    async def test_stop_calls_sniffer_stop(self, engine, mock_sniffer):
        """Stopping the engine should stop the passive sniffer."""
        await engine.start()
        await engine.stop()
        mock_sniffer.stop.assert_called_once()
        assert engine.is_running is False

    async def test_stop_sets_topology_mapper_not_running(self, engine, topology_mapper):
        """Stopping the engine should set topology mapper sniffer_running to False."""
        await engine.start()
        await engine.stop()
        assert topology_mapper.sniffer_running is False

    async def test_stop_raises_if_not_running(self, engine):
        """Stopping a non-running engine should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="not running"):
            await engine.stop()


class TestPassiveDiscoveryPipeline:
    """Tests for the passive discovery pipeline wiring."""

    async def test_passive_discovery_triggers_change_detection(
        self, engine, mock_device_repository
    ):
        """Passive discovery should run change detection on fingerprints."""
        fingerprint = DeviceFingerprint(
            protocol="modbus_tcp",
            source_address="192.168.1.10",
            destination_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_address="192.168.1.10",
            vendor="Siemens",
        )

        # Mock upsert to return a device-like object
        device_id = uuid.uuid4()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.mac_address = "aa:bb:cc:dd:ee:ff"
        mock_device.ip_address = "192.168.1.10"
        mock_device.vendor = "Siemens"
        mock_device.model = None
        mock_device.firmware_version = None
        mock_device.device_type = None
        mock_device.protocols = ["modbus_tcp"]
        mock_device.risk_score = 0
        mock_device.first_seen = datetime.now(timezone.utc)
        mock_device.last_seen = datetime.now(timezone.utc)
        mock_device.fingerprint = None

        mock_device_repository.upsert_device.return_value = (mock_device, True)

        # Call the handler directly
        await engine._handle_passive_discovery(fingerprint)

        # Verify device was upserted
        mock_device_repository.upsert_device.assert_called_once()

    async def test_passive_discovery_new_device_generates_alert(
        self, engine, mock_device_repository, mock_websocket_manager
    ):
        """New device discovery should generate a HIGH alert and broadcast it."""
        fingerprint = DeviceFingerprint(
            protocol="ethernetip",
            source_address="10.0.0.5",
            destination_address="10.0.0.1",
            mac_address="11:22:33:44:55:66",
            ip_address="10.0.0.5",
        )

        device_id = uuid.uuid4()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.mac_address = "11:22:33:44:55:66"
        mock_device.ip_address = "10.0.0.5"
        mock_device.vendor = None
        mock_device.model = None
        mock_device.firmware_version = None
        mock_device.device_type = None
        mock_device.protocols = ["ethernetip"]
        mock_device.risk_score = 0
        mock_device.first_seen = datetime.now(timezone.utc)
        mock_device.last_seen = datetime.now(timezone.utc)
        mock_device.fingerprint = None

        mock_device_repository.get_device_by_mac_ip.return_value = None
        mock_device_repository.upsert_device.return_value = (mock_device, True)

        await engine._handle_passive_discovery(fingerprint)

        # Alert should have been broadcast via WebSocket
        mock_websocket_manager.broadcast_alert.assert_called()
        # The first call should be the new_device alert
        first_call_args = mock_websocket_manager.broadcast_alert.call_args_list[0][0][0]
        assert first_call_args["alert_type"] == "new_device"
        assert first_call_args["severity"] == "HIGH"

    async def test_passive_discovery_triggers_risk_score_recalculation(
        self, engine, mock_device_repository
    ):
        """Passive discovery should trigger risk score recalculation."""
        fingerprint = DeviceFingerprint(
            protocol="modbus_tcp",
            source_address="192.168.1.10",
            destination_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_address="192.168.1.10",
        )

        device_id = uuid.uuid4()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.mac_address = "aa:bb:cc:dd:ee:ff"
        mock_device.ip_address = "192.168.1.10"
        mock_device.vendor = None
        mock_device.model = None
        mock_device.firmware_version = None
        mock_device.device_type = None
        mock_device.protocols = ["modbus_tcp"]
        mock_device.risk_score = 0
        mock_device.first_seen = datetime.now(timezone.utc)
        mock_device.last_seen = datetime.now(timezone.utc)
        mock_device.fingerprint = None

        mock_device_repository.get_device_by_mac_ip.return_value = None
        mock_device_repository.upsert_device.return_value = (mock_device, True)

        await engine._handle_passive_discovery(fingerprint)

        # Risk score should have been updated (modbus_tcp is insecure = 25 points)
        # Protocol sub-score: 25, exposure: 0, no vuln DB
        # Fallback: (0.40/0.65)*25 + (0.25/0.65)*0 = 15.38 → 15
        assert mock_device.risk_score == 15


class TestActiveProberPipeline:
    """Tests for the active probing pipeline wiring."""

    async def test_active_probe_disabled_returns_empty(self, engine):
        """Active probing should return empty list when disabled."""
        targets = [
            ProbeTarget(ip_address="192.168.1.10", protocol="modbus_tcp", port=502)
        ]
        results = await engine.run_active_probe(targets)
        assert results == []

    async def test_active_probe_enabled_calls_prober(self, engine, mock_prober):
        """Active probing should call prober when enabled."""
        engine.set_active_probing(True)
        targets = [
            ProbeTarget(ip_address="192.168.1.10", protocol="modbus_tcp", port=502)
        ]
        await engine.run_active_probe(targets)
        mock_prober.probe_batch.assert_called_once_with(targets)

    async def test_active_probe_result_triggers_inventory_update(
        self, engine, mock_device_repository
    ):
        """Active probe results should be passed to device inventory."""
        fingerprint = DeviceFingerprint(
            protocol="s7comm",
            source_address="192.168.1.20",
            destination_address="",
            mac_address="aa:bb:cc:dd:ee:01",
            ip_address="192.168.1.20",
            vendor="Siemens",
            model="S7-1200",
            firmware_version="4.5.0",
        )

        device_id = uuid.uuid4()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.mac_address = "aa:bb:cc:dd:ee:01"
        mock_device.ip_address = "192.168.1.20"
        mock_device.vendor = "Siemens"
        mock_device.model = "S7-1200"
        mock_device.firmware_version = "4.5.0"
        mock_device.device_type = None
        mock_device.protocols = ["s7comm"]
        mock_device.risk_score = 0
        mock_device.first_seen = datetime.now(timezone.utc)
        mock_device.last_seen = datetime.now(timezone.utc)
        mock_device.fingerprint = None

        mock_device_repository.get_device_by_mac_ip.return_value = None
        mock_device_repository.upsert_device.return_value = (mock_device, True)

        await engine._handle_active_probe_result(fingerprint)

        mock_device_repository.upsert_device.assert_called_once()
        call_kwargs = mock_device_repository.upsert_device.call_args[1]
        assert call_kwargs["vendor"] == "Siemens"
        assert call_kwargs["model"] == "S7-1200"
        assert call_kwargs["firmware_version"] == "4.5.0"


class TestAlertWebSocketBroadcast:
    """Tests for alert → WebSocket broadcast wiring."""

    async def test_alert_broadcast_to_websocket(
        self, engine, mock_websocket_manager
    ):
        """Alerts should be broadcast to WebSocket clients."""
        alert = Alert(
            id=uuid.uuid4(),
            alert_type="new_device",
            severity="HIGH",
            device_id=None,
            details={"ip_address": "10.0.0.1", "mac_address": "aa:bb:cc:dd:ee:ff"},
            generated_at=datetime.now(timezone.utc),
        )

        await engine._broadcast_alert_to_websocket(alert)

        mock_websocket_manager.broadcast_alert.assert_called_once()
        call_args = mock_websocket_manager.broadcast_alert.call_args[0][0]
        assert call_args["alert_type"] == "new_device"
        assert call_args["severity"] == "HIGH"

    async def test_change_detector_alerts_reach_websocket(
        self, engine, change_detector, mock_websocket_manager, mock_device_repository
    ):
        """Alerts generated by ChangeDetector should reach WebSocket."""
        fingerprint = DeviceFingerprint(
            protocol="dnp3",
            source_address="10.0.0.50",
            destination_address="10.0.0.1",
            mac_address="ff:ee:dd:cc:bb:aa",
            ip_address="10.0.0.50",
        )

        device_id = uuid.uuid4()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.mac_address = "ff:ee:dd:cc:bb:aa"
        mock_device.ip_address = "10.0.0.50"
        mock_device.vendor = None
        mock_device.model = None
        mock_device.firmware_version = None
        mock_device.device_type = None
        mock_device.protocols = ["dnp3"]
        mock_device.risk_score = 0
        mock_device.first_seen = datetime.now(timezone.utc)
        mock_device.last_seen = datetime.now(timezone.utc)
        mock_device.fingerprint = None

        mock_device_repository.get_device_by_mac_ip.return_value = None
        mock_device_repository.upsert_device.return_value = (mock_device, True)

        # Process fingerprint - should generate new_device alert
        await engine._handle_passive_discovery(fingerprint)

        # Verify WebSocket broadcast was called with the alert
        mock_websocket_manager.broadcast_alert.assert_called()


class TestRiskScorerIntegration:
    """Tests for Device Inventory → Risk Scorer wiring."""

    async def test_risk_score_calculated_on_device_update(
        self, engine, mock_device_repository
    ):
        """Risk score should be recalculated when a device is updated."""
        device_id = uuid.uuid4()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.mac_address = "aa:bb:cc:dd:ee:ff"
        mock_device.ip_address = "192.168.1.10"
        mock_device.vendor = "Schneider"
        mock_device.model = None
        mock_device.firmware_version = None
        mock_device.device_type = None
        mock_device.protocols = ["modbus_tcp", "dnp3"]  # Two insecure protocols
        mock_device.risk_score = 0
        mock_device.first_seen = datetime.now(timezone.utc)
        mock_device.last_seen = datetime.now(timezone.utc)
        mock_device.fingerprint = None

        await engine._recalculate_risk_score(mock_device)

        # Protocol sub-score: 25 + 25 = 50 (two insecure protocols)
        # Exposure sub-score: 0 (no peers)
        # Fallback (no vuln DB): (0.40/0.65)*50 + (0.25/0.65)*0 = 30.77 → 31
        assert mock_device.risk_score == 31

    async def test_risk_score_change_alert_generated(
        self, engine, mock_device_repository, mock_websocket_manager
    ):
        """Risk score change > 10 points should generate an alert."""
        device_id = uuid.uuid4()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.mac_address = "aa:bb:cc:dd:ee:ff"
        mock_device.ip_address = "192.168.1.10"
        mock_device.vendor = None
        mock_device.model = None
        mock_device.firmware_version = None
        mock_device.device_type = None
        mock_device.protocols = ["modbus_tcp", "dnp3", "ethernetip", "s7comm"]
        mock_device.risk_score = 0  # Previous score is 0
        mock_device.first_seen = datetime.now(timezone.utc)
        mock_device.last_seen = datetime.now(timezone.utc)
        mock_device.fingerprint = None

        await engine._recalculate_risk_score(mock_device)

        # Protocol sub-score: 4 * 25 = 100 (capped)
        # Exposure: 0
        # Fallback: (0.40/0.65)*100 + (0.25/0.65)*0 = 61.54 → 62
        # Change: 62 - 0 = 62 > 10, so alert should be generated
        assert mock_device.risk_score == 62
        mock_websocket_manager.broadcast_alert.assert_called()


class TestTopologyMapperIntegration:
    """Tests for Topology Mapper → Risk Scorer wiring."""

    async def test_topology_update_triggers_risk_recalculation(
        self, engine, mock_device_repository, topology_mapper
    ):
        """Topology updates should trigger risk score recalculation."""
        source_id = uuid.uuid4()
        dest_id = uuid.uuid4()

        mock_source = MagicMock()
        mock_source.id = source_id
        mock_source.mac_address = "aa:bb:cc:dd:ee:01"
        mock_source.ip_address = "192.168.1.10"
        mock_source.vendor = None
        mock_source.model = None
        mock_source.firmware_version = None
        mock_source.device_type = None
        mock_source.protocols = ["modbus_tcp"]
        mock_source.risk_score = 0
        mock_source.first_seen = datetime.now(timezone.utc)
        mock_source.last_seen = datetime.now(timezone.utc)
        mock_source.fingerprint = None

        mock_dest = MagicMock()
        mock_dest.id = dest_id
        mock_dest.mac_address = "aa:bb:cc:dd:ee:02"
        mock_dest.ip_address = "192.168.1.20"
        mock_dest.vendor = None
        mock_dest.model = None
        mock_dest.firmware_version = None
        mock_dest.device_type = None
        mock_dest.protocols = ["modbus_tcp"]
        mock_dest.risk_score = 0
        mock_dest.first_seen = datetime.now(timezone.utc)
        mock_dest.last_seen = datetime.now(timezone.utc)
        mock_dest.fingerprint = None

        mock_device_repository.get_device_by_id.side_effect = (
            lambda did: mock_source if did == source_id else mock_dest
        )

        await engine.handle_topology_update(source_id, dest_id, "modbus_tcp")

        # Both devices should have their risk scores recalculated
        # Each now has 1 peer → exposure sub-score = 25
        # Protocol: 25 (modbus_tcp insecure)
        # Fallback: (0.40/0.65)*25 + (0.25/0.65)*25 = 15.38 + 9.62 = 25
        assert mock_source.risk_score == 25
        assert mock_dest.risk_score == 25

    async def test_new_communication_path_broadcast(
        self, engine, mock_websocket_manager, mock_device_repository, topology_mapper
    ):
        """New communication paths should be broadcast via WebSocket."""
        source_id = uuid.uuid4()
        dest_id = uuid.uuid4()

        mock_device_repository.get_device_by_id.return_value = None

        await engine.handle_topology_update(source_id, dest_id, "ethernetip")

        # Should broadcast new_communication_path event
        mock_websocket_manager.broadcast_json.assert_called()
        call_args = mock_websocket_manager.broadcast_json.call_args[0][0]
        assert call_args["type"] == "new_communication_path"
        assert call_args["data"]["protocol"] == "ethernetip"


class TestActiveProbeConfiguration:
    """Tests for active probing enable/disable configuration."""

    def test_set_active_probing_enabled(self, engine):
        """Should be able to enable active probing."""
        assert engine.config.active_probing_enabled is False
        engine.set_active_probing(True)
        assert engine.config.active_probing_enabled is True

    def test_set_active_probing_disabled(self, engine):
        """Should be able to disable active probing."""
        engine.set_active_probing(True)
        engine.set_active_probing(False)
        assert engine.config.active_probing_enabled is False

    async def test_disabled_probing_skips_execution(self, engine, mock_prober):
        """Disabled probing should skip execution and return empty list."""
        engine.set_active_probing(False)
        targets = [
            ProbeTarget(ip_address="10.0.0.1", protocol="modbus_tcp", port=502),
            ProbeTarget(ip_address="10.0.0.2", protocol="s7comm", port=102),
        ]
        results = await engine.run_active_probe(targets)
        assert results == []
        mock_prober.probe_batch.assert_not_called()

    async def test_enabled_probing_executes(self, engine, mock_prober):
        """Enabled probing should execute against targets."""
        engine.set_active_probing(True)
        targets = [
            ProbeTarget(ip_address="10.0.0.1", protocol="modbus_tcp", port=502),
        ]
        await engine.run_active_probe(targets)
        mock_prober.probe_batch.assert_called_once_with(targets)


class TestPeerCountCalculation:
    """Tests for peer count calculation from topology."""

    async def test_get_peer_count_no_peers(self, engine, topology_mapper):
        """Device with no topology edges should have 0 peers."""
        device_id = uuid.uuid4()
        count = await engine._get_peer_count(device_id)
        assert count == 0

    async def test_get_peer_count_with_peers(self, engine, topology_mapper):
        """Device with topology edges should have correct peer count."""
        device_id = uuid.uuid4()
        peer1 = uuid.uuid4()
        peer2 = uuid.uuid4()

        # Record communications
        await topology_mapper.record_communication(device_id, peer1, "modbus_tcp")
        await topology_mapper.record_communication(device_id, peer2, "ethernetip")
        await topology_mapper.record_communication(peer1, device_id, "dnp3")

        count = await engine._get_peer_count(device_id)
        assert count == 2  # peer1 and peer2

    async def test_get_peer_count_deduplicates(self, engine, topology_mapper):
        """Same peer via different protocols should count as one peer."""
        device_id = uuid.uuid4()
        peer1 = uuid.uuid4()

        # Same peer, different protocols
        await topology_mapper.record_communication(device_id, peer1, "modbus_tcp")
        await topology_mapper.record_communication(device_id, peer1, "s7comm")
        await topology_mapper.record_communication(peer1, device_id, "dnp3")

        count = await engine._get_peer_count(device_id)
        assert count == 1  # Only one unique peer


class TestErrorHandling:
    """Tests for error handling in the discovery pipeline."""

    async def test_passive_discovery_handles_repository_error(
        self, engine, mock_device_repository
    ):
        """Pipeline should handle repository errors gracefully."""
        mock_device_repository.get_device_by_mac_ip.side_effect = Exception(
            "DB connection failed"
        )

        fingerprint = DeviceFingerprint(
            protocol="modbus_tcp",
            source_address="192.168.1.10",
            destination_address="192.168.1.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            ip_address="192.168.1.10",
        )

        # Should not raise - errors are logged
        await engine._handle_passive_discovery(fingerprint)

    async def test_active_probe_handles_repository_error(
        self, engine, mock_device_repository
    ):
        """Active probe pipeline should handle repository errors gracefully."""
        mock_device_repository.get_device_by_mac_ip.side_effect = Exception(
            "DB timeout"
        )

        fingerprint = DeviceFingerprint(
            protocol="s7comm",
            source_address="192.168.1.20",
            destination_address="",
            mac_address="aa:bb:cc:dd:ee:01",
            ip_address="192.168.1.20",
        )

        # Should not raise
        await engine._handle_active_probe_result(fingerprint)

    async def test_websocket_broadcast_handles_error(
        self, engine, mock_websocket_manager
    ):
        """WebSocket broadcast errors should not crash the pipeline."""
        mock_websocket_manager.broadcast_alert.side_effect = Exception(
            "WebSocket error"
        )

        alert = Alert(
            id=uuid.uuid4(),
            alert_type="new_device",
            severity="HIGH",
            device_id=None,
            details={},
            generated_at=datetime.now(timezone.utc),
        )

        # Should not raise
        await engine._broadcast_alert_to_websocket(alert)
