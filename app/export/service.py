"""Export service for generating CSV, JSON, and PDF reports.

Implements export functionality with:
- CSV export: header row with all DeviceFingerprint fields, one row per device
- JSON export: valid JSON array of DeviceFingerprint objects
- PDF report: device count summary, inventory table, topology, risk histogram, alert summary
- Same filter parameters as REST query endpoints
- Empty result handling
- 50,000 record limit enforcement
- 60-second timeout enforcement

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
"""

import asyncio
import csv
import io
import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import Alert as AlertDB, Device as DeviceModel, TopologyEdge as TopologyEdgeDB

logger = logging.getLogger(__name__)

# Maximum records allowed in a single export (Requirement 10.7)
MAX_EXPORT_RECORDS = 50_000

# Maximum time allowed for export generation in seconds (Requirement 10.6)
EXPORT_TIMEOUT_SECONDS = 60

# CSV header fields matching DeviceFingerprint schema
CSV_HEADERS = [
    "schema_version",
    "protocol",
    "source_address",
    "destination_address",
    "mac_address",
    "ip_address",
    "vendor",
    "model",
    "firmware_version",
    "device_type",
    "serial_number",
    "protocol_data",
    "parsing_status",
    "binary_fields",
]


class ExportError(Exception):
    """Base exception for export operations."""
    pass


class ExportRecordLimitExceeded(ExportError):
    """Raised when export request exceeds 50,000 records."""

    def __init__(self, count: int):
        self.count = count
        super().__init__(
            f"Export request would include {count} records, exceeding the "
            f"maximum limit of {MAX_EXPORT_RECORDS}. Please apply additional "
            f"filter criteria to reduce the result set."
        )


class ExportTimeoutError(ExportError):
    """Raised when export generation exceeds 60 seconds."""

    def __init__(self):
        super().__init__(
            "Export generation exceeded the 60-second time limit. "
            "Please apply additional filter criteria to reduce the result set."
        )


class ExportService:
    """Service for generating CSV, JSON, and PDF exports of device inventory.

    Supports the same filter parameters as the REST query endpoints:
    - vendor: case-insensitive partial match
    - model: case-insensitive partial match
    - protocol: device must have this protocol
    - subnet: device IP must be within CIDR subnet
    - risk_score_min/risk_score_max: risk score range

    Enforces:
    - Maximum 50,000 records per export (Requirement 10.7)
    - 60-second timeout (Requirement 10.6)
    - Proper empty result handling (Requirement 10.5)
    """

    def __init__(self, session: AsyncSession):
        self._session = session

    async def _build_filtered_query(
        self,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
        subnet: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
    ):
        """Build a SQLAlchemy query with the same filters as REST endpoints.

        Returns both a data query and a count query with filters applied.
        """
        stmt = select(DeviceModel)
        count_stmt = select(func.count(DeviceModel.id))

        if vendor is not None:
            stmt = stmt.where(DeviceModel.vendor.ilike(f"%{vendor}%"))
            count_stmt = count_stmt.where(DeviceModel.vendor.ilike(f"%{vendor}%"))

        if model is not None:
            stmt = stmt.where(DeviceModel.model.ilike(f"%{model}%"))
            count_stmt = count_stmt.where(DeviceModel.model.ilike(f"%{model}%"))

        if protocol is not None:
            stmt = stmt.where(DeviceModel.protocols.any(protocol))
            count_stmt = count_stmt.where(DeviceModel.protocols.any(protocol))

        if subnet is not None:
            subnet_filter = DeviceModel.ip_address.op("<<=")(text(f"'{subnet}'::cidr"))
            stmt = stmt.where(subnet_filter)
            count_stmt = count_stmt.where(subnet_filter)

        if risk_score_min is not None:
            stmt = stmt.where(DeviceModel.risk_score >= risk_score_min)
            count_stmt = count_stmt.where(DeviceModel.risk_score >= risk_score_min)

        if risk_score_max is not None:
            stmt = stmt.where(DeviceModel.risk_score <= risk_score_max)
            count_stmt = count_stmt.where(DeviceModel.risk_score <= risk_score_max)

        return stmt, count_stmt

    async def _get_record_count(
        self,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
        subnet: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
    ) -> int:
        """Get the count of records matching the filter criteria."""
        _, count_stmt = await self._build_filtered_query(
            vendor=vendor,
            model=model,
            protocol=protocol,
            subnet=subnet,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )
        result = await self._session.execute(count_stmt)
        return result.scalar_one()

    async def _fetch_devices(
        self,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
        subnet: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
    ) -> list[DeviceModel]:
        """Fetch all devices matching the filter criteria."""
        stmt, _ = await self._build_filtered_query(
            vendor=vendor,
            model=model,
            protocol=protocol,
            subnet=subnet,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )
        stmt = stmt.order_by(DeviceModel.last_seen.desc())
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    def _device_to_fingerprint_dict(self, device: DeviceModel) -> dict:
        """Convert a device record to a DeviceFingerprint-compatible dict.

        If the device has a stored fingerprint, uses that. Otherwise,
        constructs a fingerprint from the device's attributes.
        """
        if device.fingerprint is not None:
            return device.fingerprint

        # Construct a fingerprint from device attributes
        protocols = device.protocols or []
        protocol = protocols[0] if protocols else "modbus_tcp"

        return {
            "schema_version": "1.0.0",
            "protocol": protocol,
            "source_address": str(device.ip_address),
            "destination_address": "",
            "mac_address": str(device.mac_address),
            "ip_address": str(device.ip_address),
            "vendor": device.vendor,
            "model": device.model,
            "firmware_version": device.firmware_version,
            "device_type": device.device_type,
            "serial_number": None,
            "protocol_data": {},
            "parsing_status": "complete",
            "binary_fields": {},
        }

    async def _validate_record_count(
        self,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
        subnet: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
    ) -> int:
        """Validate that the record count doesn't exceed the limit.

        Returns the count if valid, raises ExportRecordLimitExceeded otherwise.
        """
        count = await self._get_record_count(
            vendor=vendor,
            model=model,
            protocol=protocol,
            subnet=subnet,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )
        if count > MAX_EXPORT_RECORDS:
            raise ExportRecordLimitExceeded(count)
        return count

    async def export_csv(
        self,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
        subnet: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
    ) -> str:
        """Generate a CSV export of device inventory.

        Returns a CSV string with a header row listing all DeviceFingerprint
        fields and one data row per matching device.

        For empty results, returns headers only (Requirement 10.5).
        Rejects requests exceeding 50,000 records (Requirement 10.7).
        Must complete within 60 seconds (Requirement 10.6).

        Args:
            vendor: Filter by vendor (case-insensitive partial match).
            model: Filter by model (case-insensitive partial match).
            protocol: Filter by protocol.
            subnet: Filter by subnet (CIDR notation).
            risk_score_min: Minimum risk score filter.
            risk_score_max: Maximum risk score filter.

        Returns:
            CSV string with headers and data rows.

        Raises:
            ExportRecordLimitExceeded: If matching records exceed 50,000.
            ExportTimeoutError: If generation exceeds 60 seconds.
        """
        # Validate record count
        await self._validate_record_count(
            vendor=vendor, model=model, protocol=protocol,
            subnet=subnet, risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )

        start_time = datetime.now(timezone.utc)

        # Fetch devices
        devices = await self._fetch_devices(
            vendor=vendor, model=model, protocol=protocol,
            subnet=subnet, risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )

        # Check timeout
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise ExportTimeoutError()

        # Generate CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_HEADERS, extrasaction="ignore")
        writer.writeheader()

        for device in devices:
            fp_dict = self._device_to_fingerprint_dict(device)
            # Serialize complex fields to JSON strings for CSV
            row = {}
            for header in CSV_HEADERS:
                value = fp_dict.get(header)
                if isinstance(value, (dict, list)):
                    row[header] = json.dumps(value)
                elif value is None:
                    row[header] = ""
                else:
                    row[header] = str(value)
            writer.writerow(row)

            # Periodic timeout check
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed > EXPORT_TIMEOUT_SECONDS:
                raise ExportTimeoutError()

        return output.getvalue()

    async def export_json(
        self,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
        subnet: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
    ) -> str:
        """Generate a JSON export of device inventory.

        Returns a valid JSON array where each element is a DeviceFingerprint
        object conforming to the schema.

        For empty results, returns an empty array "[]" (Requirement 10.5).
        Rejects requests exceeding 50,000 records (Requirement 10.7).
        Must complete within 60 seconds (Requirement 10.6).

        Args:
            vendor: Filter by vendor (case-insensitive partial match).
            model: Filter by model (case-insensitive partial match).
            protocol: Filter by protocol.
            subnet: Filter by subnet (CIDR notation).
            risk_score_min: Minimum risk score filter.
            risk_score_max: Maximum risk score filter.

        Returns:
            JSON string containing an array of DeviceFingerprint objects.

        Raises:
            ExportRecordLimitExceeded: If matching records exceed 50,000.
            ExportTimeoutError: If generation exceeds 60 seconds.
        """
        # Validate record count
        await self._validate_record_count(
            vendor=vendor, model=model, protocol=protocol,
            subnet=subnet, risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )

        start_time = datetime.now(timezone.utc)

        # Fetch devices
        devices = await self._fetch_devices(
            vendor=vendor, model=model, protocol=protocol,
            subnet=subnet, risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )

        # Check timeout
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise ExportTimeoutError()

        # Build JSON array
        fingerprints = []
        for device in devices:
            fp_dict = self._device_to_fingerprint_dict(device)
            fingerprints.append(fp_dict)

            # Periodic timeout check
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed > EXPORT_TIMEOUT_SECONDS:
                raise ExportTimeoutError()

        return json.dumps(fingerprints, indent=2, default=str)

    async def export_pdf(
        self,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
        subnet: Optional[str] = None,
        risk_score_min: Optional[int] = None,
        risk_score_max: Optional[int] = None,
    ) -> str:
        """Generate a PDF report of device inventory.

        Since we don't have a PDF library dependency, this generates a
        structured text report that can be rendered as PDF by the caller.
        The report includes:
        - Device count summary with breakdown by vendor and protocol
        - Device inventory table listing all matching devices
        - Textual description of observed communication paths
        - Histogram of risk score distribution
        - Summary of alerts generated within the preceding 30 days

        For empty results, returns a report stating "no devices matched"
        (Requirement 10.5).

        Args:
            vendor: Filter by vendor (case-insensitive partial match).
            model: Filter by model (case-insensitive partial match).
            protocol: Filter by protocol.
            subnet: Filter by subnet (CIDR notation).
            risk_score_min: Minimum risk score filter.
            risk_score_max: Maximum risk score filter.

        Returns:
            Structured text report content.

        Raises:
            ExportRecordLimitExceeded: If matching records exceed 50,000.
            ExportTimeoutError: If generation exceeds 60 seconds.
        """
        # Validate record count
        await self._validate_record_count(
            vendor=vendor, model=model, protocol=protocol,
            subnet=subnet, risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )

        start_time = datetime.now(timezone.utc)

        # Fetch devices
        devices = await self._fetch_devices(
            vendor=vendor, model=model, protocol=protocol,
            subnet=subnet, risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )

        # Check timeout after fetch
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise ExportTimeoutError()

        # Handle empty results (Requirement 10.5)
        if not devices:
            return self._generate_empty_pdf_report()

        # Build report sections
        report_sections = []

        # Title
        report_sections.append("=" * 60)
        report_sections.append("OT ASSET DISCOVERY - INVENTORY REPORT")
        report_sections.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_sections.append("=" * 60)
        report_sections.append("")

        # 1. Device count summary by vendor and protocol
        report_sections.append(self._generate_vendor_summary(devices))

        # Check timeout
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise ExportTimeoutError()

        report_sections.append(self._generate_protocol_summary(devices))

        # 2. Device inventory table
        report_sections.append(self._generate_inventory_table(devices))

        # Check timeout
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise ExportTimeoutError()

        # 3. Topology description
        topology_desc = await self._generate_topology_description(devices)
        report_sections.append(topology_desc)

        # Check timeout
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise ExportTimeoutError()

        # 4. Risk score histogram
        report_sections.append(self._generate_risk_histogram(devices))

        # 5. 30-day alert summary
        alert_summary = await self._generate_alert_summary(devices)
        report_sections.append(alert_summary)

        # Final timeout check
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise ExportTimeoutError()

        return "\n".join(report_sections)

    def _generate_empty_pdf_report(self) -> str:
        """Generate a PDF report for empty results."""
        lines = [
            "=" * 60,
            "OT ASSET DISCOVERY - INVENTORY REPORT",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "=" * 60,
            "",
            "No devices matched the specified filter criteria.",
            "",
            "Please adjust your filter parameters and try again.",
        ]
        return "\n".join(lines)

    def _generate_vendor_summary(self, devices: list[DeviceModel]) -> str:
        """Generate device count summary by vendor."""
        lines = [
            "-" * 40,
            "DEVICE COUNT SUMMARY BY VENDOR",
            "-" * 40,
            f"Total Devices: {len(devices)}",
            "",
        ]

        vendor_counts = Counter(
            device.vendor or "Unknown" for device in devices
        )
        for vendor_name, count in vendor_counts.most_common():
            lines.append(f"  {vendor_name}: {count}")

        lines.append("")
        return "\n".join(lines)

    def _generate_protocol_summary(self, devices: list[DeviceModel]) -> str:
        """Generate device count summary by protocol."""
        lines = [
            "-" * 40,
            "DEVICE COUNT SUMMARY BY PROTOCOL",
            "-" * 40,
        ]

        protocol_counts: Counter = Counter()
        for device in devices:
            for proto in (device.protocols or []):
                protocol_counts[proto] += 1

        if not protocol_counts:
            lines.append("  No protocols detected")
        else:
            for proto_name, count in protocol_counts.most_common():
                lines.append(f"  {proto_name}: {count}")

        lines.append("")
        return "\n".join(lines)

    def _generate_inventory_table(self, devices: list[DeviceModel]) -> str:
        """Generate device inventory table."""
        lines = [
            "-" * 40,
            "DEVICE INVENTORY TABLE",
            "-" * 40,
            f"{'IP Address':<18} {'MAC Address':<20} {'Vendor':<15} {'Model':<15} {'Type':<6} {'Risk':<5} {'Last Seen'}",
            "-" * 100,
        ]

        for device in devices:
            ip = str(device.ip_address)[:17]
            mac = str(device.mac_address)[:19]
            vendor_str = (device.vendor or "N/A")[:14]
            model_str = (device.model or "N/A")[:14]
            dtype = (device.device_type or "N/A")[:5]
            risk = str(device.risk_score or 0)
            last_seen = device.last_seen.strftime("%Y-%m-%d %H:%M") if device.last_seen else "N/A"
            lines.append(
                f"  {ip:<18} {mac:<20} {vendor_str:<15} {model_str:<15} {dtype:<6} {risk:<5} {last_seen}"
            )

        lines.append("")
        return "\n".join(lines)

    async def _generate_topology_description(self, devices: list[DeviceModel]) -> str:
        """Generate textual description of observed communication paths."""
        lines = [
            "-" * 40,
            "NETWORK TOPOLOGY - COMMUNICATION PATHS",
            "-" * 40,
        ]

        # Get device IDs for the filtered set
        device_ids = [device.id for device in devices]

        if not device_ids:
            lines.append("  No communication paths observed.")
            lines.append("")
            return "\n".join(lines)

        # Query topology edges involving these devices
        stmt = select(TopologyEdgeDB).where(
            (TopologyEdgeDB.source_device_id.in_(device_ids))
            | (TopologyEdgeDB.dest_device_id.in_(device_ids))
        ).order_by(TopologyEdgeDB.packet_count.desc())

        result = await self._session.execute(stmt)
        edges = result.scalars().all()

        if not edges:
            lines.append("  No communication paths observed.")
            lines.append("")
            return "\n".join(lines)

        # Build device IP lookup
        device_ip_map = {device.id: str(device.ip_address) for device in devices}

        lines.append(f"  Total communication paths: {len(edges)}")
        lines.append("")

        for edge in edges[:50]:  # Limit to top 50 paths
            src_ip = device_ip_map.get(edge.source_device_id, str(edge.source_device_id)[:8])
            dst_ip = device_ip_map.get(edge.dest_device_id, str(edge.dest_device_id)[:8])
            lines.append(
                f"  {src_ip} -> {dst_ip} via {edge.protocol} "
                f"({edge.packet_count} packets, last seen: {edge.last_seen.strftime('%Y-%m-%d %H:%M') if edge.last_seen else 'N/A'})"
            )

        if len(edges) > 50:
            lines.append(f"  ... and {len(edges) - 50} more paths")

        lines.append("")
        return "\n".join(lines)

    def _generate_risk_histogram(self, devices: list[DeviceModel]) -> str:
        """Generate risk score distribution histogram."""
        lines = [
            "-" * 40,
            "RISK SCORE DISTRIBUTION",
            "-" * 40,
        ]

        # Define risk buckets
        buckets = {
            "0-20 (Low)": 0,
            "21-40 (Low-Medium)": 0,
            "41-60 (Medium)": 0,
            "61-80 (High)": 0,
            "81-100 (Critical)": 0,
        }

        for device in devices:
            score = device.risk_score or 0
            if score <= 20:
                buckets["0-20 (Low)"] += 1
            elif score <= 40:
                buckets["21-40 (Low-Medium)"] += 1
            elif score <= 60:
                buckets["41-60 (Medium)"] += 1
            elif score <= 80:
                buckets["61-80 (High)"] += 1
            else:
                buckets["81-100 (Critical)"] += 1

        max_count = max(buckets.values()) if buckets.values() else 1
        bar_width = 30

        for bucket_name, count in buckets.items():
            bar_length = int((count / max_count) * bar_width) if max_count > 0 else 0
            bar = "█" * bar_length
            lines.append(f"  {bucket_name:<22} | {bar:<{bar_width}} | {count}")

        lines.append("")
        return "\n".join(lines)

    async def _generate_alert_summary(self, devices: list[DeviceModel]) -> str:
        """Generate summary of alerts from the preceding 30 days."""
        lines = [
            "-" * 40,
            "30-DAY ALERT SUMMARY",
            "-" * 40,
        ]

        # Get device IDs
        device_ids = [device.id for device in devices]

        # Query alerts from last 30 days for these devices
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

        stmt = select(AlertDB).where(
            AlertDB.generated_at >= thirty_days_ago,
            AlertDB.device_id.in_(device_ids),
        )
        result = await self._session.execute(stmt)
        alerts = result.scalars().all()

        if not alerts:
            lines.append("  No alerts generated in the last 30 days.")
            lines.append("")
            return "\n".join(lines)

        lines.append(f"  Total alerts: {len(alerts)}")
        lines.append("")

        # By severity
        severity_counts = Counter(alert.severity for alert in alerts)
        lines.append("  By Severity:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"    {severity}: {count}")

        lines.append("")

        # By type
        type_counts = Counter(alert.alert_type for alert in alerts)
        lines.append("  By Type:")
        for alert_type, count in type_counts.most_common():
            lines.append(f"    {alert_type}: {count}")

        lines.append("")
        return "\n".join(lines)
