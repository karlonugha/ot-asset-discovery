"""Active device prober for OT Asset Discovery.

Sends protocol-specific identity requests to target devices with concurrency
control and timeout/retry logic. Supports Modbus TCP, EtherNet/IP, S7comm,
and DNP3 protocols.

The ActiveProber:
- Probes individual devices with a 5-second timeout and 1 retry (10s max)
- Limits concurrent probes to 10 via asyncio.Semaphore
- Records timeout and error results in Scan_Job history
- Passes valid DeviceFingerprint results to Device_Inventory

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.8, 3.9
"""

import asyncio
import logging
import struct
import time
from typing import Callable, Optional, Awaitable

from app.models.domain import DeviceFingerprint, ProbeResult, ProbeTarget, ParseResult
from app.parsers.modbus import parse_modbus
from app.parsers.ethernetip import parse_ethernetip
from app.parsers.s7comm import parse_s7comm
from app.parsers.dnp3 import parse_dnp3

logger = logging.getLogger(__name__)


# Default port mappings for OT protocols
DEFAULT_PORTS = {
    "modbus_tcp": 502,
    "ethernetip": 44818,
    "s7comm": 102,
    "dnp3": 20000,
}


class ActiveProber:
    """Active device prober with concurrency control and retry logic.

    Sends protocol-specific identity requests to OT devices and parses
    responses into DeviceFingerprint objects.

    Attributes:
        MAX_CONCURRENT: Maximum number of concurrent probes (10).
        TIMEOUT_SECONDS: Timeout per probe attempt (5 seconds).
        MAX_RETRIES: Number of retry attempts (1, for 10s total max).
    """

    MAX_CONCURRENT: int = 10
    TIMEOUT_SECONDS: float = 5.0
    MAX_RETRIES: int = 1

    def __init__(
        self,
        on_result: Optional[Callable[[DeviceFingerprint], Awaitable[None]]] = None,
        on_scan_history: Optional[Callable[[dict], Awaitable[None]]] = None,
    ):
        """Initialize the ActiveProber.

        Args:
            on_result: Async callback invoked with valid DeviceFingerprint results.
                       Used to pass results to Device_Inventory.
            on_scan_history: Async callback invoked with scan history entries
                            (timeout/error records for Scan_Job history).
        """
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        self._on_result = on_result
        self._on_scan_history = on_scan_history

    async def probe_device(self, target: ProbeTarget) -> ProbeResult:
        """Probe a single device with timeout and retry.

        Sends a protocol-specific identity request to the target device.
        If the first attempt times out, retries once. Total maximum elapsed
        time is 10 seconds (5s timeout × 2 attempts).

        Args:
            target: ProbeTarget specifying IP, protocol, and port.

        Returns:
            ProbeResult with status "success", "timeout", or "error",
            and a DeviceFingerprint if identity data was extracted.

        Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
        """
        start_time = time.monotonic()
        last_error: Optional[str] = None

        for attempt in range(1 + self.MAX_RETRIES):
            try:
                result = await asyncio.wait_for(
                    self._send_probe(target),
                    timeout=self.TIMEOUT_SECONDS,
                )
                elapsed_ms = (time.monotonic() - start_time) * 1000

                if result.fingerprint is not None:
                    probe_result = ProbeResult(
                        target=target,
                        status="success",
                        fingerprint=result.fingerprint,
                        elapsed_ms=elapsed_ms,
                    )
                    # Pass valid fingerprint to Device_Inventory
                    if self._on_result and result.fingerprint:
                        try:
                            await self._on_result(result.fingerprint)
                        except Exception as e:
                            logger.error(
                                f"Error passing fingerprint to inventory: {e}"
                            )
                    return probe_result

                if result.error:
                    last_error = result.error
                    # Error response - record and continue to retry
                    if attempt < self.MAX_RETRIES:
                        continue

                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    probe_result = ProbeResult(
                        target=target,
                        status="error",
                        error_code=result.error,
                        elapsed_ms=elapsed_ms,
                    )
                    await self._record_history(target, probe_result)
                    return probe_result

                # No fingerprint and no error - no identity data in response
                elapsed_ms = (time.monotonic() - start_time) * 1000
                return ProbeResult(
                    target=target,
                    status="success",
                    fingerprint=None,
                    elapsed_ms=elapsed_ms,
                )

            except asyncio.TimeoutError:
                last_error = "timeout"
                if attempt < self.MAX_RETRIES:
                    logger.debug(
                        f"Probe timeout for {target.ip_address}:{target.port} "
                        f"({target.protocol}), retrying..."
                    )
                    continue

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    f"Probe error for {target.ip_address}:{target.port} "
                    f"({target.protocol}): {e}"
                )
                if attempt < self.MAX_RETRIES:
                    continue

        # All attempts exhausted
        elapsed_ms = (time.monotonic() - start_time) * 1000
        status = "timeout" if last_error == "timeout" else "error"
        probe_result = ProbeResult(
            target=target,
            status=status,
            error_code=last_error,
            elapsed_ms=elapsed_ms,
        )
        await self._record_history(target, probe_result)
        return probe_result

    async def probe_batch(self, targets: list[ProbeTarget]) -> list[ProbeResult]:
        """Probe multiple devices with concurrency limit of 10.

        Uses asyncio.Semaphore to ensure no more than MAX_CONCURRENT (10)
        probes execute simultaneously.

        Args:
            targets: List of ProbeTarget objects to probe.

        Returns:
            List of ProbeResult objects, one per target, in the same order.

        Requirements: 3.9
        """
        if not targets:
            return []

        async def _limited_probe(target: ProbeTarget) -> ProbeResult:
            async with self._semaphore:
                return await self.probe_device(target)

        tasks = [asyncio.create_task(_limited_probe(t)) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert any exceptions to error ProbeResults
        final_results: list[ProbeResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    f"Unexpected error probing {targets[i].ip_address}: {result}"
                )
                final_results.append(
                    ProbeResult(
                        target=targets[i],
                        status="error",
                        error_code=str(result),
                        elapsed_ms=0.0,
                    )
                )
            else:
                final_results.append(result)

        return final_results

    async def _send_probe(self, target: ProbeTarget) -> ParseResult:
        """Send a protocol-specific probe request and parse the response.

        Establishes a TCP connection to the target, sends the appropriate
        identity request, and parses the response using the protocol parser.

        Args:
            target: ProbeTarget with IP, protocol, and port.

        Returns:
            ParseResult from the protocol parser.
        """
        request_bytes = self._build_probe_request(target.protocol)

        try:
            reader, writer = await asyncio.open_connection(
                target.ip_address, target.port
            )
        except (ConnectionRefusedError, OSError) as e:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol=target.protocol,
                source_address=target.ip_address,
                destination_address="",
                error=f"Connection failed: {e}",
            )

        try:
            writer.write(request_bytes)
            await writer.drain()

            # Read response with a reasonable buffer size
            response = await reader.read(4096)

            if not response:
                return ParseResult(
                    fingerprint=None,
                    parsing_status="no_identity",
                    protocol=target.protocol,
                    source_address=target.ip_address,
                    destination_address="",
                    error="Empty response",
                )

            # Parse response using the appropriate protocol parser
            return self._parse_response(target, response)

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _build_probe_request(self, protocol: str) -> bytes:
        """Build a protocol-specific identity probe request.

        Args:
            protocol: One of "modbus_tcp", "ethernetip", "s7comm", "dnp3".

        Returns:
            Raw bytes of the probe request packet.
        """
        if protocol == "modbus_tcp":
            return self._build_modbus_device_id_request()
        elif protocol == "ethernetip":
            return self._build_ethernetip_list_identity_request()
        elif protocol == "s7comm":
            return self._build_s7comm_szl_request()
        elif protocol == "dnp3":
            return self._build_dnp3_device_attributes_request()
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def _build_modbus_device_id_request(self) -> bytes:
        """Build a Modbus TCP Read Device Identification request.

        Function code 0x2B, MEI type 0x0E, Read Device ID code 0x01 (basic).

        Frame structure:
          MBAP Header: Transaction ID(2) + Protocol ID(2) + Length(2) + Unit ID(1)
          PDU: Function Code(1) + MEI Type(1) + Read Device ID Code(1) + Object ID(1)

        Requirements: 3.1
        """
        transaction_id = 0x0001
        protocol_id = 0x0000
        unit_id = 0x01
        function_code = 0x2B
        mei_type = 0x0E
        read_device_id_code = 0x01  # Basic device identification
        object_id = 0x00  # Start from VendorName

        pdu = struct.pack(
            ">BBBB",
            function_code,
            mei_type,
            read_device_id_code,
            object_id,
        )
        length = len(pdu) + 1  # +1 for Unit ID

        mbap_header = struct.pack(
            ">HHHB",
            transaction_id,
            protocol_id,
            length,
            unit_id,
        )

        return mbap_header + pdu

    def _build_ethernetip_list_identity_request(self) -> bytes:
        """Build an EtherNet/IP List Identity request.

        Command 0x0063 with empty data payload.

        Frame structure:
          Encapsulation Header (24 bytes):
            Command(2) + Length(2) + Session Handle(4) + Status(4) +
            Sender Context(8) + Options(4)

        Requirements: 3.2
        """
        command = 0x0063  # List Identity
        length = 0  # No command-specific data
        session_handle = 0x00000000
        status = 0x00000000
        sender_context = b"\x00" * 8
        options = 0x00000000

        header = struct.pack(
            "<HHI I",
            command,
            length,
            session_handle,
            status,
        )
        header += sender_context
        header += struct.pack("<I", options)

        return header

    def _build_s7comm_szl_request(self) -> bytes:
        """Build an S7comm SZL Read request for CPU identification.

        Sends a TPKT + COTP + S7comm Userdata request to read SZL 0x001C
        (Component Identification).

        The full request includes:
        1. COTP Connection Request (to establish COTP session)
        2. S7comm Setup Communication
        3. S7comm Read SZL

        For simplicity, this builds the SZL read request assuming an
        established connection. The connection setup is handled separately.

        Requirements: 3.3
        """
        # Build S7comm Read SZL request
        # S7comm header
        s7_protocol_id = 0x32
        s7_msg_type = 0x07  # Userdata
        s7_reserved = 0x0000
        s7_pdu_ref = 0x0100

        # Userdata parameter (12 bytes)
        param = bytes([
            0x00, 0x01, 0x12,  # Parameter head
            0x04,              # Parameter length (remaining)
            0x11,              # Method: request
            0x44,              # Type/function: 0x4=request, 0x4=CPU functions
            0x01,              # Subfunction: Read SZL
            0x00,              # Sequence number
        ])

        # Data section: SZL request
        # Return code(1) + Transport size(1) + Length(2) + SZL ID(2) + SZL Index(2)
        szl_id = 0x001C  # Component Identification
        szl_index = 0x0000  # All records
        data = struct.pack(
            ">BBH HH",
            0x0A,   # Return code (not used in request, set to 0x0A)
            0x00,   # Transport size
            0x04,   # Data length (4 bytes: SZL ID + Index)
            szl_id,
            szl_index,
        )

        param_length = len(param)
        data_length = len(data)

        s7_header = struct.pack(
            ">BBHHH H",
            s7_protocol_id,
            s7_msg_type,
            s7_reserved,
            s7_pdu_ref,
            param_length,
            data_length,
        )

        s7_payload = s7_header + param + data

        # COTP Data PDU header (3 bytes)
        cotp_header = bytes([
            0x02,  # Header length (2 bytes follow)
            0xF0,  # PDU type: Data Transfer
            0x80,  # TPDU number + EOT flag
        ])

        # TPKT header
        tpkt_length = 4 + len(cotp_header) + len(s7_payload)
        tpkt_header = struct.pack(
            ">BBH",
            0x03,  # Version
            0x00,  # Reserved
            tpkt_length,
        )

        return tpkt_header + cotp_header + s7_payload

    def _build_dnp3_device_attributes_request(self) -> bytes:
        """Build a DNP3 Device Attributes request.

        Sends Object Group 0, Variation 254 (All Attributes) request.

        Frame structure:
          Data Link Layer: Start(2) + Length(1) + Control(1) + Dest(2) + Source(2) + CRC(2)
          Transport Layer: Transport header(1)
          Application Layer: App Control(1) + Function Code(1) + Object Header(3+)

        Requirements: 3.4
        """
        # Application layer
        app_control = 0xC0  # FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
        function_code = 0x01  # Read request

        # Object header for Group 0, Variation 254 (All Attributes)
        # Qualifier 0x06 = all objects (no range)
        object_header = bytes([
            0x00,  # Object group: 0 (Device Attributes)
            0xFE,  # Variation: 254 (All attributes)
            0x06,  # Qualifier: all objects
        ])

        app_layer = bytes([app_control, function_code]) + object_header

        # Transport layer
        transport_header = 0xC0  # FIR=1, FIN=1, SEQ=0

        user_data = bytes([transport_header]) + app_layer

        # Data Link Layer
        start_bytes = b"\x05\x64"
        # Length = 5 (control + dest + source) + len(user_data)
        length = 5 + len(user_data)
        control = 0xC4  # DIR=1, PRM=1, FCB=1, FCV=0, FC=4 (Unconfirmed User Data)
        destination = 0x0001  # Default destination address
        source = 0x0003  # Default source (master) address

        # Build header block (without CRC for simplicity - real implementation
        # would compute CRC-16 per DNP3 spec)
        header = start_bytes + struct.pack("<BBH H", length, control, destination, source)

        # CRC placeholder (2 bytes) - in production, compute proper CRC-16
        header_crc = self._compute_dnp3_crc(header[0:8])
        header_with_crc = header + header_crc

        # Data block with CRC
        data_block = user_data
        data_crc = self._compute_dnp3_crc(data_block)

        return header_with_crc + data_block + data_crc

    def _compute_dnp3_crc(self, data: bytes) -> bytes:
        """Compute DNP3 CRC-16 for a data block.

        Uses the DNP3 CRC polynomial (x^16 + x^13 + x^12 + x^11 + x^10 +
        x^8 + x^6 + x^5 + x^2 + 1).

        Args:
            data: Bytes to compute CRC over.

        Returns:
            2-byte CRC in little-endian format.
        """
        crc = 0x0000
        for byte in data:
            for _ in range(8):
                if (crc ^ byte) & 0x0001:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc = crc >> 1
                byte >>= 1
        crc = ~crc & 0xFFFF
        return struct.pack("<H", crc)

    def _parse_response(self, target: ProbeTarget, response: bytes) -> ParseResult:
        """Parse a probe response using the appropriate protocol parser.

        Args:
            target: The probe target (for address context).
            response: Raw response bytes from the device.

        Returns:
            ParseResult from the protocol-specific parser.
        """
        if target.protocol == "modbus_tcp":
            return parse_modbus(
                response,
                source_address=target.ip_address,
                destination_address="",
            )
        elif target.protocol == "ethernetip":
            return parse_ethernetip(response)
        elif target.protocol == "s7comm":
            return parse_s7comm(response)
        elif target.protocol == "dnp3":
            return parse_dnp3(response)
        else:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol=target.protocol,
                source_address=target.ip_address,
                destination_address="",
                error=f"Unsupported protocol: {target.protocol}",
            )

    async def _record_history(self, target: ProbeTarget, result: ProbeResult) -> None:
        """Record a probe result (timeout/error) in Scan_Job history.

        Args:
            target: The probe target.
            result: The probe result to record.

        Requirements: 3.5, 3.6
        """
        history_entry = {
            "ip_address": target.ip_address,
            "protocol": target.protocol,
            "port": target.port,
            "status": result.status,
            "error_code": result.error_code,
            "elapsed_ms": result.elapsed_ms,
        }

        logger.info(
            f"Probe {result.status} for {target.ip_address}:{target.port} "
            f"({target.protocol}): {result.error_code}"
        )

        if self._on_scan_history:
            try:
                await self._on_scan_history(history_entry)
            except Exception as e:
                logger.error(f"Error recording scan history: {e}")
