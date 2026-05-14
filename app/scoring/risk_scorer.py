"""Risk scoring engine for OT devices.

Calculates composite risk scores from protocol security posture,
vulnerability severity, and network exposure factors.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from app.models.domain import Alert, Device

logger = logging.getLogger(__name__)

# Protocols considered insecure (unencrypted, no authentication)
INSECURE_PROTOCOLS = frozenset({
    "modbus_tcp",
    "dnp3",
    "ethernetip",
    "s7comm",
    "bacnet",
    "profinet",
    "opcua_unsecured",
})

# Protocols considered secure (encrypted or authenticated)
SECURE_PROTOCOLS = frozenset({
    "dnp3_sa",  # DNP3 with Secure Authentication
    "opcua",
    "tls",
    "ipsec",
    "mqtt_tls",
    "https",
})

# CVE severity to sub-score mapping
VULNERABILITY_SEVERITY_SCORES = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "none": 0,
}


class VulnerabilityDBUnavailableError(Exception):
    """Raised when the vulnerability database cannot be reached."""
    pass


class RiskScorer:
    """Calculates composite risk scores for OT devices.

    The score is a weighted sum of three factors:
    - Protocol risk (40%): Based on insecure vs secure protocols
    - Vulnerability risk (35%): Based on highest CVE severity
    - Network exposure risk (25%): Based on communication peer count

    Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8
    """

    PROTOCOL_WEIGHT = 0.40
    VULNERABILITY_WEIGHT = 0.35
    EXPOSURE_WEIGHT = 0.25

    def __init__(
        self,
        vulnerability_db: Optional["VulnerabilityDB"] = None,
        alert_callback: Optional[callable] = None,
    ):
        """Initialize the RiskScorer.

        Args:
            vulnerability_db: Optional vulnerability database interface for
                looking up CVE severities by firmware version.
            alert_callback: Optional callback invoked when a risk_score_change
                alert is generated. Signature: callback(alert: Alert) -> None.
        """
        self._vulnerability_db = vulnerability_db
        self._alert_callback = alert_callback

    def protocol_sub_score(self, protocols: list[str]) -> int:
        """Calculate protocol risk sub-score.

        Each insecure protocol contributes 25 points.
        Each secure protocol contributes 5 points.
        Protocols not in either list are treated as insecure (25 points)
        since unknown protocols in OT environments are a risk.
        The sub-score is capped at 100.

        Args:
            protocols: List of protocol identifiers detected on the device.

        Returns:
            Integer sub-score from 0 to 100.

        Requirement: 7.3
        """
        if not protocols:
            return 0

        score = 0
        for protocol in protocols:
            protocol_lower = protocol.lower()
            if protocol_lower in SECURE_PROTOCOLS:
                score += 5
            else:
                # Insecure or unknown protocols get 25 points
                score += 25

        return min(100, score)

    def vulnerability_sub_score(
        self, firmware: Optional[str], device_id: Optional[UUID] = None
    ) -> int:
        """Calculate vulnerability risk sub-score.

        Based on the highest CVE severity associated with the device's
        firmware version from the configured vulnerability database.

        Severity mapping:
        - Critical = 100
        - High = 75
        - Medium = 50
        - Low = 25
        - None = 0

        Args:
            firmware: Firmware version string to look up.
            device_id: Optional device ID for logging context.

        Returns:
            Integer sub-score from 0 to 100.

        Raises:
            VulnerabilityDBUnavailableError: When the vulnerability DB
                cannot be reached.

        Requirement: 7.4
        """
        if self._vulnerability_db is None:
            raise VulnerabilityDBUnavailableError(
                "No vulnerability database configured"
            )

        if firmware is None:
            return 0

        try:
            severity = self._vulnerability_db.get_highest_severity(firmware)
        except Exception as e:
            raise VulnerabilityDBUnavailableError(
                f"Vulnerability database unavailable: {e}"
            ) from e

        severity_lower = severity.lower() if severity else "none"
        return VULNERABILITY_SEVERITY_SCORES.get(severity_lower, 0)

    def exposure_sub_score(self, peer_count: int) -> int:
        """Calculate network exposure risk sub-score.

        Based on the number of unique communication peers observed
        by the Topology Mapper:
        - 0 peers → 0
        - 1-5 peers → 25
        - 6-15 peers → 50
        - 16-30 peers → 75
        - >30 peers → 100

        Args:
            peer_count: Number of unique communication peers.

        Returns:
            Integer sub-score from 0 to 100.

        Requirement: 7.5
        """
        if peer_count <= 0:
            return 0
        elif peer_count <= 5:
            return 25
        elif peer_count <= 15:
            return 50
        elif peer_count <= 30:
            return 75
        else:
            return 100

    def calculate_score(
        self,
        device: Device,
        peer_count: int = 0,
        previous_score: Optional[int] = None,
    ) -> "RiskScoreResult":
        """Calculate the composite risk score for a device.

        Computes the weighted sum:
            score = round(0.40 × protocol + 0.35 × vulnerability + 0.25 × exposure)

        If the vulnerability database is unavailable, falls back to
        re-normalizing protocol and exposure weights to 100%:
            score = round((0.40/0.65) × protocol + (0.25/0.65) × exposure)

        Triggers a "risk_score_change" alert when the score changes by
        more than 10 points compared to the previous score.

        Args:
            device: The device to score.
            peer_count: Number of unique communication peers for this device.
            previous_score: The device's previously stored risk score, if any.

        Returns:
            RiskScoreResult containing the score, sub-scores, and any alert.

        Requirements: 7.1, 7.2, 7.6, 7.7, 7.8
        """
        # Calculate protocol sub-score
        proto_score = self.protocol_sub_score(device.protocols)

        # Calculate exposure sub-score
        expo_score = self.exposure_sub_score(peer_count)

        # Attempt vulnerability sub-score
        vuln_score: Optional[int] = None
        vuln_db_available = True

        try:
            vuln_score = self.vulnerability_sub_score(
                device.firmware_version, device.id
            )
        except VulnerabilityDBUnavailableError as e:
            vuln_db_available = False
            logger.warning(
                "Vulnerability DB unavailable for device %s: %s",
                device.id,
                e,
            )

        # Calculate final score
        if vuln_db_available and vuln_score is not None:
            # Normal calculation with all three factors
            raw_score = (
                self.PROTOCOL_WEIGHT * proto_score
                + self.VULNERABILITY_WEIGHT * vuln_score
                + self.EXPOSURE_WEIGHT * expo_score
            )
        else:
            # Fallback: re-normalize protocol + exposure to 100%
            # Combined weight = 0.40 + 0.25 = 0.65
            combined_weight = self.PROTOCOL_WEIGHT + self.EXPOSURE_WEIGHT
            raw_score = (
                (self.PROTOCOL_WEIGHT / combined_weight) * proto_score
                + (self.EXPOSURE_WEIGHT / combined_weight) * expo_score
            )

        # Round and clamp to 0-100
        final_score = max(0, min(100, round(raw_score)))

        # Check if alert should be triggered (score change > 10 points)
        alert: Optional[Alert] = None
        if previous_score is not None:
            score_change = abs(final_score - previous_score)
            if score_change > 10:
                alert = Alert(
                    id=uuid4(),
                    alert_type="risk_score_change",
                    severity="MEDIUM",
                    device_id=device.id,
                    details={
                        "previous_score": previous_score,
                        "new_score": final_score,
                        "change": final_score - previous_score,
                    },
                    generated_at=datetime.now(timezone.utc),
                )
                if self._alert_callback:
                    self._alert_callback(alert)

        return RiskScoreResult(
            score=final_score,
            protocol_sub_score=proto_score,
            vulnerability_sub_score=vuln_score,
            exposure_sub_score=expo_score,
            vuln_db_available=vuln_db_available,
            alert=alert,
        )


class RiskScoreResult:
    """Result of a risk score calculation.

    Contains the final score, individual sub-scores, and any generated alert.
    """

    def __init__(
        self,
        score: int,
        protocol_sub_score: int,
        vulnerability_sub_score: Optional[int],
        exposure_sub_score: int,
        vuln_db_available: bool,
        alert: Optional[Alert] = None,
    ):
        self.score = score
        self.protocol_sub_score = protocol_sub_score
        self.vulnerability_sub_score = vulnerability_sub_score
        self.exposure_sub_score = exposure_sub_score
        self.vuln_db_available = vuln_db_available
        self.alert = alert


class VulnerabilityDB:
    """Interface for vulnerability database lookups.

    Implementations should connect to a CVE database and return
    the highest severity for a given firmware version.
    """

    def get_highest_severity(self, firmware_version: str) -> str:
        """Look up the highest CVE severity for a firmware version.

        Args:
            firmware_version: The firmware version string to look up.

        Returns:
            Severity string: "critical", "high", "medium", "low", or "none".

        Raises:
            Exception: If the database is unreachable.
        """
        raise NotImplementedError("Subclasses must implement get_highest_severity")
