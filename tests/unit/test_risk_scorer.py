"""Unit tests for the RiskScorer class.

Tests cover:
- Protocol sub-score calculation (Requirement 7.3)
- Vulnerability sub-score calculation (Requirement 7.4)
- Exposure sub-score calculation (Requirement 7.5)
- Weighted sum calculation (Requirement 7.2)
- Fallback when vulnerability DB unavailable (Requirement 7.6)
- Risk score change alert threshold (Requirement 7.8)
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4

from app.models.domain import Device
from app.scoring.risk_scorer import (
    RiskScorer,
    RiskScoreResult,
    VulnerabilityDB,
    VulnerabilityDBUnavailableError,
)


class MockVulnerabilityDB(VulnerabilityDB):
    """Mock vulnerability database for testing."""

    def __init__(self, severity_map: dict[str, str] = None, unavailable: bool = False):
        self._severity_map = severity_map or {}
        self._unavailable = unavailable

    def get_highest_severity(self, firmware_version: str) -> str:
        if self._unavailable:
            raise ConnectionError("Database unreachable")
        return self._severity_map.get(firmware_version, "none")


def make_device(
    protocols: list[str] = None,
    firmware_version: str = None,
    risk_score: int = 0,
) -> Device:
    """Helper to create a Device instance for testing."""
    return Device(
        id=uuid4(),
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.100",
        vendor="TestVendor",
        model="TestModel",
        firmware_version=firmware_version,
        protocols=protocols or [],
        risk_score=risk_score,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )


class TestProtocolSubScore:
    """Tests for protocol_sub_score() - Requirement 7.3."""

    def test_empty_protocols_returns_zero(self):
        scorer = RiskScorer()
        assert scorer.protocol_sub_score([]) == 0

    def test_single_insecure_protocol(self):
        scorer = RiskScorer()
        assert scorer.protocol_sub_score(["modbus_tcp"]) == 25

    def test_single_secure_protocol(self):
        scorer = RiskScorer()
        assert scorer.protocol_sub_score(["opcua"]) == 5

    def test_multiple_insecure_protocols(self):
        scorer = RiskScorer()
        assert scorer.protocol_sub_score(["modbus_tcp", "dnp3", "s7comm"]) == 75

    def test_four_insecure_protocols_equals_100(self):
        scorer = RiskScorer()
        result = scorer.protocol_sub_score(
            ["modbus_tcp", "dnp3", "s7comm", "ethernetip"]
        )
        assert result == 100

    def test_cap_at_100(self):
        scorer = RiskScorer()
        # 5 insecure protocols = 125, but capped at 100
        result = scorer.protocol_sub_score(
            ["modbus_tcp", "dnp3", "s7comm", "ethernetip", "bacnet"]
        )
        assert result == 100

    def test_mixed_protocols(self):
        scorer = RiskScorer()
        # 2 insecure (50) + 1 secure (5) = 55
        result = scorer.protocol_sub_score(["modbus_tcp", "dnp3", "opcua"])
        assert result == 55

    def test_unknown_protocol_treated_as_insecure(self):
        scorer = RiskScorer()
        # Unknown protocol gets 25 points
        assert scorer.protocol_sub_score(["unknown_proto"]) == 25

    def test_all_secure_protocols(self):
        scorer = RiskScorer()
        # 3 secure protocols = 15
        result = scorer.protocol_sub_score(["opcua", "tls", "dnp3_sa"])
        assert result == 15

    def test_case_insensitive(self):
        scorer = RiskScorer()
        assert scorer.protocol_sub_score(["MODBUS_TCP"]) == 25
        assert scorer.protocol_sub_score(["OPCUA"]) == 5


class TestVulnerabilitySubScore:
    """Tests for vulnerability_sub_score() - Requirement 7.4."""

    def test_critical_severity(self):
        db = MockVulnerabilityDB({"fw1.0": "critical"})
        scorer = RiskScorer(vulnerability_db=db)
        assert scorer.vulnerability_sub_score("fw1.0") == 100

    def test_high_severity(self):
        db = MockVulnerabilityDB({"fw2.0": "high"})
        scorer = RiskScorer(vulnerability_db=db)
        assert scorer.vulnerability_sub_score("fw2.0") == 75

    def test_medium_severity(self):
        db = MockVulnerabilityDB({"fw3.0": "medium"})
        scorer = RiskScorer(vulnerability_db=db)
        assert scorer.vulnerability_sub_score("fw3.0") == 50

    def test_low_severity(self):
        db = MockVulnerabilityDB({"fw4.0": "low"})
        scorer = RiskScorer(vulnerability_db=db)
        assert scorer.vulnerability_sub_score("fw4.0") == 25

    def test_none_severity(self):
        db = MockVulnerabilityDB({"fw5.0": "none"})
        scorer = RiskScorer(vulnerability_db=db)
        assert scorer.vulnerability_sub_score("fw5.0") == 0

    def test_no_firmware_returns_zero(self):
        db = MockVulnerabilityDB()
        scorer = RiskScorer(vulnerability_db=db)
        assert scorer.vulnerability_sub_score(None) == 0

    def test_unknown_firmware_returns_zero(self):
        db = MockVulnerabilityDB({})
        scorer = RiskScorer(vulnerability_db=db)
        assert scorer.vulnerability_sub_score("unknown_fw") == 0

    def test_no_db_raises_error(self):
        scorer = RiskScorer(vulnerability_db=None)
        with pytest.raises(VulnerabilityDBUnavailableError):
            scorer.vulnerability_sub_score("fw1.0")

    def test_db_connection_error_raises(self):
        db = MockVulnerabilityDB(unavailable=True)
        scorer = RiskScorer(vulnerability_db=db)
        with pytest.raises(VulnerabilityDBUnavailableError):
            scorer.vulnerability_sub_score("fw1.0")


class TestExposureSubScore:
    """Tests for exposure_sub_score() - Requirement 7.5."""

    def test_zero_peers(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(0) == 0

    def test_negative_peers_returns_zero(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(-1) == 0

    def test_one_peer(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(1) == 25

    def test_five_peers(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(5) == 25

    def test_six_peers(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(6) == 50

    def test_fifteen_peers(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(15) == 50

    def test_sixteen_peers(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(16) == 75

    def test_thirty_peers(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(30) == 75

    def test_thirty_one_peers(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(31) == 100

    def test_large_peer_count(self):
        scorer = RiskScorer()
        assert scorer.exposure_sub_score(1000) == 100


class TestCalculateScore:
    """Tests for calculate_score() - Requirements 7.1, 7.2."""

    def test_all_zeros(self):
        scorer = RiskScorer(vulnerability_db=MockVulnerabilityDB())
        device = make_device(protocols=[], firmware_version=None)
        result = scorer.calculate_score(device, peer_count=0)
        assert result.score == 0

    def test_weighted_sum_calculation(self):
        """Verify: round(0.40 * protocol + 0.35 * vulnerability + 0.25 * exposure)"""
        db = MockVulnerabilityDB({"fw1.0": "high"})
        scorer = RiskScorer(vulnerability_db=db)
        device = make_device(
            protocols=["modbus_tcp", "dnp3"],  # 50 protocol score
            firmware_version="fw1.0",  # 75 vulnerability score
        )
        result = scorer.calculate_score(device, peer_count=10)  # 50 exposure score

        # Expected: round(0.40*50 + 0.35*75 + 0.25*50) = round(20 + 26.25 + 12.5) = round(58.75) = 59
        assert result.score == 59
        assert result.protocol_sub_score == 50
        assert result.vulnerability_sub_score == 75
        assert result.exposure_sub_score == 50
        assert result.vuln_db_available is True

    def test_max_score(self):
        """All sub-scores at 100 should produce final score of 100."""
        db = MockVulnerabilityDB({"fw_crit": "critical"})
        scorer = RiskScorer(vulnerability_db=db)
        device = make_device(
            protocols=["modbus_tcp", "dnp3", "s7comm", "ethernetip"],  # 100
            firmware_version="fw_crit",  # 100
        )
        result = scorer.calculate_score(device, peer_count=50)  # 100

        # round(0.40*100 + 0.35*100 + 0.25*100) = round(100) = 100
        assert result.score == 100

    def test_score_clamped_to_100(self):
        """Score should never exceed 100."""
        db = MockVulnerabilityDB({"fw_crit": "critical"})
        scorer = RiskScorer(vulnerability_db=db)
        device = make_device(
            protocols=["modbus_tcp", "dnp3", "s7comm", "ethernetip", "bacnet"],
            firmware_version="fw_crit",
        )
        result = scorer.calculate_score(device, peer_count=100)
        assert result.score <= 100

    def test_result_contains_all_sub_scores(self):
        db = MockVulnerabilityDB({"fw1.0": "medium"})
        scorer = RiskScorer(vulnerability_db=db)
        device = make_device(protocols=["modbus_tcp"], firmware_version="fw1.0")
        result = scorer.calculate_score(device, peer_count=3)

        assert isinstance(result, RiskScoreResult)
        assert result.protocol_sub_score == 25
        assert result.vulnerability_sub_score == 50
        assert result.exposure_sub_score == 25


class TestFallbackScoring:
    """Tests for vulnerability DB fallback - Requirement 7.6."""

    def test_fallback_when_no_db_configured(self):
        """When no vuln DB, use re-normalized protocol + exposure."""
        scorer = RiskScorer(vulnerability_db=None)
        device = make_device(protocols=["modbus_tcp", "dnp3"])  # 50 protocol
        result = scorer.calculate_score(device, peer_count=10)  # 50 exposure

        # Fallback: round((0.40/0.65)*50 + (0.25/0.65)*50)
        # = round(0.6154*50 + 0.3846*50)
        # = round(30.77 + 19.23)
        # = round(50.0) = 50
        assert result.score == 50
        assert result.vuln_db_available is False
        assert result.vulnerability_sub_score is None

    def test_fallback_when_db_unreachable(self):
        """When vuln DB raises error, fall back to protocol + exposure."""
        db = MockVulnerabilityDB(unavailable=True)
        scorer = RiskScorer(vulnerability_db=db)
        device = make_device(
            protocols=["modbus_tcp"],  # 25 protocol
            firmware_version="fw1.0",
        )
        result = scorer.calculate_score(device, peer_count=20)  # 75 exposure

        # Fallback: round((0.40/0.65)*25 + (0.25/0.65)*75)
        # = round(0.6154*25 + 0.3846*75)
        # = round(15.385 + 28.846)
        # = round(44.23) = 44
        assert result.score == 44
        assert result.vuln_db_available is False

    def test_fallback_zero_scores(self):
        """Fallback with zero sub-scores should produce 0."""
        scorer = RiskScorer(vulnerability_db=None)
        device = make_device(protocols=[])
        result = scorer.calculate_score(device, peer_count=0)
        assert result.score == 0


class TestRiskScoreChangeAlert:
    """Tests for risk score change alert - Requirement 7.8."""

    def test_no_alert_when_no_previous_score(self):
        scorer = RiskScorer(vulnerability_db=MockVulnerabilityDB())
        device = make_device(protocols=["modbus_tcp"])
        result = scorer.calculate_score(device, peer_count=5, previous_score=None)
        assert result.alert is None

    def test_no_alert_when_change_is_10_or_less(self):
        db = MockVulnerabilityDB({"fw1.0": "low"})
        scorer = RiskScorer(vulnerability_db=db)
        device = make_device(protocols=["modbus_tcp"], firmware_version="fw1.0")
        result = scorer.calculate_score(device, peer_count=3)

        # Now test with previous score within 10 points
        actual_score = result.score
        result2 = scorer.calculate_score(
            device, peer_count=3, previous_score=actual_score - 10
        )
        assert result2.alert is None

        result3 = scorer.calculate_score(
            device, peer_count=3, previous_score=actual_score + 10
        )
        assert result3.alert is None

    def test_alert_when_change_exceeds_10(self):
        db = MockVulnerabilityDB({"fw_crit": "critical"})
        scorer = RiskScorer(vulnerability_db=db)
        device = make_device(
            protocols=["modbus_tcp", "dnp3", "s7comm"],
            firmware_version="fw_crit",
        )
        # This should produce a high score
        result = scorer.calculate_score(device, peer_count=20, previous_score=10)

        assert result.alert is not None
        assert result.alert.alert_type == "risk_score_change"
        assert result.alert.severity == "MEDIUM"
        assert result.alert.device_id == device.id
        assert result.alert.details["previous_score"] == 10
        assert result.alert.details["new_score"] == result.score
        assert abs(result.alert.details["change"]) > 10

    def test_alert_callback_invoked(self):
        alerts_received = []
        db = MockVulnerabilityDB({"fw_crit": "critical"})
        scorer = RiskScorer(
            vulnerability_db=db,
            alert_callback=lambda a: alerts_received.append(a),
        )
        device = make_device(
            protocols=["modbus_tcp", "dnp3", "s7comm", "ethernetip"],
            firmware_version="fw_crit",
        )
        scorer.calculate_score(device, peer_count=50, previous_score=0)

        assert len(alerts_received) == 1
        assert alerts_received[0].alert_type == "risk_score_change"

    def test_no_callback_when_no_alert(self):
        alerts_received = []
        db = MockVulnerabilityDB({"fw1.0": "none"})
        scorer = RiskScorer(
            vulnerability_db=db,
            alert_callback=lambda a: alerts_received.append(a),
        )
        device = make_device(protocols=["opcua"], firmware_version="fw1.0")
        # Score will be low, set previous to same value
        result = scorer.calculate_score(device, peer_count=0)
        scorer.calculate_score(
            device, peer_count=0, previous_score=result.score
        )
        assert len(alerts_received) == 0

    def test_alert_on_score_decrease(self):
        """Alert should trigger on decrease > 10 as well."""
        scorer = RiskScorer(vulnerability_db=MockVulnerabilityDB())
        device = make_device(protocols=[])
        # Score will be 0, previous was 50 → change of 50
        result = scorer.calculate_score(device, peer_count=0, previous_score=50)
        assert result.alert is not None
        assert result.alert.details["change"] < 0
