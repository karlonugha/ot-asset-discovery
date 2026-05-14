"""Passive network sniffer for OT protocol traffic capture.

Uses Scapy's AsyncSniffer in promiscuous mode to capture Ethernet frames
on a specified network interface. Routes captured packets to protocol parsers
and commits extracted device information to the Device Inventory.

Requirements: 1.1, 1.3, 1.5, 1.6, 1.7
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from scapy.all import AsyncSniffer, conf, get_if_list
from scapy.packet import Packet

from app.models.domain import DeviceFingerprint, ParseResult
from app.parsers.modbus import parse_modbus
from app.parsers.ethernetip import parse_ethernetip
from app.parsers.s7comm import parse_s7comm
from app.parsers.dnp3 import parse_dnp3

logger = logging.getLogger(__name__)

# OT protocol port mappings for routing
MODBUS_TCP_PORT = 502
ETHERNETIP_TCP_PORT = 44818
ETHERNETIP_UDP_PORT = 2222
S7COMM_PORT = 102
DNP3_PORT = 20000

# Flush timeout in seconds when stopping the sniffer
FLUSH_TIMEOUT_SECONDS = 30


class InterfaceError(Exception):
    """Raised when a network interface is unavailable or invalid."""

    def __init__(self, interface: str, reason: str = ""):
        self.interface = interface
        self.reason = reason
        message = f"Interface '{interface}' is unavailable"
        if reason:
            message += f": {reason}"
        super().__init__(message)


class PassiveSniffer:
    """Manages passive network traffic capture using Scapy's AsyncSniffer.

    Captures all Ethernet frames in promiscuous mode on a specified interface,
    routes OT protocol packets to appropriate parsers, and commits extracted
    device information to the Device Inventory.

    Attributes:
        interface: The network interface being captured on.
        is_running: Whether the sniffer is currently capturing packets.
    """

    def __init__(self) -> None:
        """Initialize the PassiveSniffer."""
        self._sniffer: Optional[AsyncSniffer] = None
        self._interface: Optional[str] = None
        self._is_running: bool = False
        self._packet_callbacks: list[Callable[[bytes], Awaitable[None]]] = []
        self._buffer: list[DeviceFingerprint] = []
        self._buffer_lock: asyncio.Lock = asyncio.Lock()
        self._commit_callback: Optional[Callable[[DeviceFingerprint], Awaitable[None]]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._started_at: Optional[datetime] = None

    @property
    def interface(self) -> Optional[str]:
        """The network interface currently being captured on."""
        return self._interface

    @property
    def is_running(self) -> bool:
        """Whether the sniffer is currently capturing packets."""
        return self._is_running

    @property
    def started_at(self) -> Optional[datetime]:
        """Timestamp when the sniffer was last started."""
        return self._started_at

    def on_packet(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Register a packet handler callback.

        The callback will be invoked with raw packet bytes for each
        captured frame. Multiple callbacks can be registered.

        Args:
            callback: Async function that receives raw packet bytes.
        """
        self._packet_callbacks.append(callback)

    def on_device_discovered(
        self, callback: Callable[[DeviceFingerprint], Awaitable[None]]
    ) -> None:
        """Register a callback for when a device fingerprint is extracted.

        This callback is invoked when a protocol parser successfully extracts
        device identity information from a captured packet. The callback should
        commit the fingerprint to the Device Inventory.

        Args:
            callback: Async function that receives a DeviceFingerprint.
        """
        self._commit_callback = callback

    async def start(self, interface: str) -> None:
        """Start capturing packets on the specified network interface.

        Validates the interface is available, then starts Scapy's AsyncSniffer
        in promiscuous mode. Raises InterfaceError if the interface cannot be
        accessed.

        Args:
            interface: Name of the network interface to capture on.

        Raises:
            InterfaceError: If the interface is unavailable or invalid.
            RuntimeError: If the sniffer is already running.
        """
        if self._is_running:
            raise RuntimeError("Sniffer is already running")

        # Validate interface availability (Requirement 1.6)
        self._validate_interface(interface)

        self._interface = interface
        self._loop = asyncio.get_event_loop()
        self._buffer = []

        # Start AsyncSniffer in promiscuous mode (Requirement 1.1)
        try:
            self._sniffer = AsyncSniffer(
                iface=interface,
                prn=self._packet_handler,
                store=False,  # Don't store packets in memory
                promisc=True,  # Promiscuous mode
            )
            self._sniffer.start()
            self._is_running = True
            self._started_at = datetime.now(timezone.utc)
            logger.info(
                "Passive sniffer started on interface '%s' in promiscuous mode",
                interface,
            )
        except Exception as e:
            self._is_running = False
            self._sniffer = None
            raise InterfaceError(
                interface, f"Failed to start capture: {e}"
            ) from e

    async def stop(self) -> None:
        """Stop packet capture and flush buffered data.

        Stops the AsyncSniffer and flushes all buffered device fingerprints
        to the Device Inventory within 30 seconds (Requirement 1.5).
        If the flush exceeds 30 seconds, logs an error with the number of
        unflushed records (Requirement 1.7).

        Raises:
            RuntimeError: If the sniffer is not running.
        """
        if not self._is_running:
            raise RuntimeError("Sniffer is not running")

        # Stop the Scapy sniffer
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.error("Error stopping sniffer: %s", e)

        self._is_running = False

        # Flush buffered data within 30 seconds (Requirement 1.5, 1.7)
        await self._flush_buffer()

        self._sniffer = None
        logger.info("Passive sniffer stopped on interface '%s'", self._interface)

    async def _flush_buffer(self) -> None:
        """Flush all buffered fingerprints to the Device Inventory.

        Attempts to commit all buffered records within FLUSH_TIMEOUT_SECONDS.
        If the timeout is exceeded, logs an error with the count of unflushed
        records but does not lose previously committed entries.
        """
        async with self._buffer_lock:
            if not self._buffer:
                return

            total_records = len(self._buffer)
            committed = 0

            try:
                async with asyncio.timeout(FLUSH_TIMEOUT_SECONDS):
                    for fingerprint in self._buffer:
                        if self._commit_callback:
                            await self._commit_callback(fingerprint)
                            committed += 1
                    self._buffer.clear()
                    logger.info(
                        "Flushed %d buffered records to Device Inventory",
                        committed,
                    )
            except TimeoutError:
                unflushed = total_records - committed
                # Remove committed records from buffer
                self._buffer = self._buffer[committed:]
                logger.error(
                    "Flush timeout exceeded (%ds). %d of %d records unflushed. "
                    "Previously committed entries are preserved.",
                    FLUSH_TIMEOUT_SECONDS,
                    unflushed,
                    total_records,
                )
            except Exception as e:
                unflushed = total_records - committed
                self._buffer = self._buffer[committed:]
                logger.error(
                    "Flush failed after committing %d of %d records: %s. "
                    "%d records unflushed.",
                    committed,
                    total_records,
                    e,
                    unflushed,
                )

    def _validate_interface(self, interface: str) -> None:
        """Validate that the specified network interface is available.

        Args:
            interface: Name of the network interface to validate.

        Raises:
            InterfaceError: If the interface is not found or cannot be accessed.
        """
        if not interface or not interface.strip():
            raise InterfaceError(interface, "Interface name cannot be empty")

        try:
            available_interfaces = get_if_list()
        except Exception as e:
            raise InterfaceError(
                interface, f"Cannot enumerate network interfaces: {e}"
            ) from e

        if interface not in available_interfaces:
            raise InterfaceError(
                interface,
                f"Interface not found. Available interfaces: {available_interfaces}",
            )

    def _packet_handler(self, packet: Packet) -> None:
        """Scapy packet callback invoked for each captured frame.

        Routes the packet to registered callbacks and protocol parsers.
        Handles malformed packets gracefully by logging errors with metadata
        (Requirement 1.4).

        This runs in Scapy's sniffer thread, so we schedule async work
        on the event loop.

        Args:
            packet: Scapy Packet object representing the captured frame.
        """
        try:
            raw_bytes = bytes(packet)
            timestamp = datetime.now(timezone.utc)

            # Extract packet metadata for error logging
            src_mac = packet.src if hasattr(packet, "src") else "unknown"
            dst_mac = packet.dst if hasattr(packet, "dst") else "unknown"
            frame_length = len(raw_bytes)

            # Schedule async processing on the event loop
            if self._loop and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self._process_packet(
                        raw_bytes, timestamp, src_mac, dst_mac, frame_length
                    ),
                    self._loop,
                )
        except Exception as e:
            # Never let an exception propagate to Scapy's capture loop
            logger.error(
                "Unhandled error in packet handler: %s", e, exc_info=True
            )

    async def _process_packet(
        self,
        raw_bytes: bytes,
        timestamp: datetime,
        src_mac: str,
        dst_mac: str,
        frame_length: int,
    ) -> None:
        """Process a captured packet asynchronously.

        Invokes registered callbacks and routes the packet to the appropriate
        protocol parser based on port numbers. Commits extracted device
        information within 500ms of receipt (Requirement 1.3).

        Args:
            raw_bytes: Raw packet bytes.
            timestamp: Capture timestamp.
            src_mac: Source MAC address.
            dst_mac: Destination MAC address.
            frame_length: Total frame length in bytes.
        """
        start_time = time.monotonic()

        # Invoke registered packet callbacks
        for callback in self._packet_callbacks:
            try:
                await callback(raw_bytes)
            except Exception as e:
                logger.error("Packet callback error: %s", e)

        # Route to protocol parser
        try:
            parse_result = self._route_to_parser(raw_bytes, src_mac, dst_mac)

            if parse_result and parse_result.fingerprint:
                # Commit to Device Inventory within 500ms (Requirement 1.3)
                fingerprint = parse_result.fingerprint
                fingerprint.mac_address = src_mac
                if fingerprint.ip_address is None:
                    fingerprint.ip_address = self._extract_ip(raw_bytes)

                if self._commit_callback:
                    await self._commit_callback(fingerprint)
                else:
                    # Buffer if no commit callback registered
                    async with self._buffer_lock:
                        self._buffer.append(fingerprint)

                elapsed_ms = (time.monotonic() - start_time) * 1000
                if elapsed_ms > 500:
                    logger.warning(
                        "Device commit took %.1fms (exceeds 500ms target) "
                        "for packet from %s",
                        elapsed_ms,
                        src_mac,
                    )

        except Exception as e:
            # Malformed packet handling (Requirement 1.4)
            protocol_type = self._identify_protocol(raw_bytes)
            logger.error(
                "Malformed packet error: %s | metadata: timestamp=%s, "
                "src_mac=%s, dst_mac=%s, frame_length=%d, protocol=%s",
                e,
                timestamp.isoformat(),
                src_mac,
                dst_mac,
                frame_length,
                protocol_type or "unknown",
            )

    def _route_to_parser(
        self, raw_bytes: bytes, src_mac: str, dst_mac: str
    ) -> Optional[ParseResult]:
        """Route a packet to the appropriate OT protocol parser.

        Identifies the protocol based on TCP/UDP port numbers in the packet
        and dispatches to the corresponding parser.

        Args:
            raw_bytes: Raw packet bytes (full Ethernet frame).
            src_mac: Source MAC address.
            dst_mac: Destination MAC address.

        Returns:
            ParseResult from the protocol parser, or None if no OT protocol
            is identified.
        """
        protocol_info = self._identify_protocol(raw_bytes)
        if protocol_info is None:
            return None

        # Extract the protocol payload (skip Ethernet + IP + TCP/UDP headers)
        payload = self._extract_payload(raw_bytes)
        if payload is None or len(payload) == 0:
            return None

        src_ip = self._extract_src_ip(raw_bytes)
        dst_ip = self._extract_dst_ip(raw_bytes)
        src_addr = src_ip or src_mac
        dst_addr = dst_ip or dst_mac

        if protocol_info == "modbus_tcp":
            return parse_modbus(payload, source_address=src_addr, destination_address=dst_addr)
        elif protocol_info == "ethernetip":
            return parse_ethernetip(payload)
        elif protocol_info == "s7comm":
            return parse_s7comm(payload)
        elif protocol_info == "dnp3":
            return parse_dnp3(payload)

        return None

    def _identify_protocol(self, raw_bytes: bytes) -> Optional[str]:
        """Identify the OT protocol in a packet based on port numbers.

        Examines TCP/UDP destination and source ports to determine which
        OT protocol the packet belongs to.

        Args:
            raw_bytes: Raw packet bytes (full Ethernet frame).

        Returns:
            Protocol identifier string or None if not an OT protocol.
        """
        if len(raw_bytes) < 34:  # Minimum: Ethernet(14) + IP(20)
            return None

        # Check EtherType (bytes 12-13 of Ethernet frame)
        ethertype = int.from_bytes(raw_bytes[12:14], "big")
        if ethertype != 0x0800:  # Not IPv4
            return None

        # IP header starts at byte 14
        ip_header_start = 14
        if len(raw_bytes) < ip_header_start + 20:
            return None

        # IP header length (IHL field, lower nibble of first byte * 4)
        ihl = (raw_bytes[ip_header_start] & 0x0F) * 4
        ip_protocol = raw_bytes[ip_header_start + 9]  # Protocol field

        # TCP = 6, UDP = 17
        if ip_protocol not in (6, 17):
            return None

        # Transport header starts after IP header
        transport_start = ip_header_start + ihl
        if len(raw_bytes) < transport_start + 4:  # Need at least src+dst port
            return None

        src_port = int.from_bytes(raw_bytes[transport_start:transport_start + 2], "big")
        dst_port = int.from_bytes(raw_bytes[transport_start + 2:transport_start + 4], "big")

        # Match ports to OT protocols
        if src_port == MODBUS_TCP_PORT or dst_port == MODBUS_TCP_PORT:
            return "modbus_tcp"
        elif src_port == ETHERNETIP_TCP_PORT or dst_port == ETHERNETIP_TCP_PORT:
            return "ethernetip"
        elif src_port == ETHERNETIP_UDP_PORT or dst_port == ETHERNETIP_UDP_PORT:
            return "ethernetip"
        elif src_port == S7COMM_PORT or dst_port == S7COMM_PORT:
            return "s7comm"
        elif src_port == DNP3_PORT or dst_port == DNP3_PORT:
            return "dnp3"

        return None

    def _extract_payload(self, raw_bytes: bytes) -> Optional[bytes]:
        """Extract the application-layer payload from a packet.

        Strips Ethernet, IP, and TCP/UDP headers to get the protocol payload.

        Args:
            raw_bytes: Raw packet bytes (full Ethernet frame).

        Returns:
            Application-layer payload bytes, or None if extraction fails.
        """
        if len(raw_bytes) < 34:
            return None

        # Ethernet header is 14 bytes
        ip_header_start = 14

        # IP header length
        ihl = (raw_bytes[ip_header_start] & 0x0F) * 4
        ip_protocol = raw_bytes[ip_header_start + 9]

        transport_start = ip_header_start + ihl

        # TCP header length (data offset field) or UDP header (always 8 bytes)
        if ip_protocol == 6:  # TCP
            if len(raw_bytes) < transport_start + 13:
                return None
            tcp_data_offset = ((raw_bytes[transport_start + 12] >> 4) & 0x0F) * 4
            payload_start = transport_start + tcp_data_offset
        elif ip_protocol == 17:  # UDP
            payload_start = transport_start + 8
        else:
            return None

        if payload_start >= len(raw_bytes):
            return None

        return raw_bytes[payload_start:]

    def _extract_ip(self, raw_bytes: bytes) -> Optional[str]:
        """Extract the source IP address from a packet.

        Args:
            raw_bytes: Raw packet bytes (full Ethernet frame).

        Returns:
            Source IP address as string, or None if extraction fails.
        """
        return self._extract_src_ip(raw_bytes)

    def _extract_src_ip(self, raw_bytes: bytes) -> Optional[str]:
        """Extract source IP address from packet bytes.

        Args:
            raw_bytes: Raw packet bytes (full Ethernet frame).

        Returns:
            Source IP address as dotted-quad string, or None.
        """
        if len(raw_bytes) < 30:  # Ethernet(14) + IP src addr ends at byte 30
            return None

        # Check EtherType
        ethertype = int.from_bytes(raw_bytes[12:14], "big")
        if ethertype != 0x0800:
            return None

        # Source IP is at offset 26-29 in the frame (14 + 12)
        ip_start = 14
        src_ip_bytes = raw_bytes[ip_start + 12:ip_start + 16]
        return f"{src_ip_bytes[0]}.{src_ip_bytes[1]}.{src_ip_bytes[2]}.{src_ip_bytes[3]}"

    def _extract_dst_ip(self, raw_bytes: bytes) -> Optional[str]:
        """Extract destination IP address from packet bytes.

        Args:
            raw_bytes: Raw packet bytes (full Ethernet frame).

        Returns:
            Destination IP address as dotted-quad string, or None.
        """
        if len(raw_bytes) < 34:  # Ethernet(14) + IP dst addr ends at byte 34
            return None

        # Check EtherType
        ethertype = int.from_bytes(raw_bytes[12:14], "big")
        if ethertype != 0x0800:
            return None

        # Destination IP is at offset 30-33 in the frame (14 + 16)
        ip_start = 14
        dst_ip_bytes = raw_bytes[ip_start + 16:ip_start + 20]
        return f"{dst_ip_bytes[0]}.{dst_ip_bytes[1]}.{dst_ip_bytes[2]}.{dst_ip_bytes[3]}"
