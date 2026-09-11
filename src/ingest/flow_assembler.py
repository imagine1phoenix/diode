"""
Flow Assembler — Groups raw packets into flow records.

PRD §5: Operates between ingest and feature extraction.
rules.md R1: Read-only, no outbound network calls.
rules.md R6.3: Ingest layer has no dependency on detection logic.

A flow is identified by a 5-tuple: (src_ip, src_port, dst_ip, dst_port, proto).
Flows are considered complete after FLOW_TIMEOUT_SECONDS of inactivity.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Generator

from src.ingest.reader import RawPacket

logger = logging.getLogger(__name__)


@dataclass
class FlowRecord:
    """
    Aggregated flow record — the primary unit of analysis for all detectors.

    Contains all information derivable from a one-way tap for a single
    network flow (5-tuple conversation).
    """

    # Flow identity
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str

    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    timestamps: list[float] = field(default_factory=list)

    # Volume
    packet_count: int = 0
    total_bytes: int = 0
    packet_sizes: list[int] = field(default_factory=list)
    payload_sizes: list[int] = field(default_factory=list)

    # TCP flags
    flags_list: list[str] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    # DNS (if applicable)
    dns_queries: list[str] = field(default_factory=list)
    dns_qtypes: list[str] = field(default_factory=list)

    # TLS (Tier 2)
    tls_ja3_fingerprints: list[str] = field(default_factory=list)

    # Bidirectional visibility (when return link is mirrored into diode tap)
    reverse_bytes: int = 0
    reverse_packets: int = 0

    @property
    def flow_id(self) -> str:
        """Format: src_ip:src_port-dst_ip:dst_port-proto (PRD §6, R4.3)."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.proto}"

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        if self.end_time > self.start_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def bytes_per_packet(self) -> float:
        """Average bytes per packet."""
        if self.packet_count == 0:
            return 0.0
        return self.total_bytes / self.packet_count


MAX_FLOW_SAMPLES: int = 500  # Cap per-flow sample lists to prevent memory leaks during high-rate bursts


class FlowAssembler:
    """
    Assembles RawPacket objects into FlowRecord objects.

    Packets are grouped by 5-tuple. A flow is emitted when it exceeds
    the configured timeout since its last packet or is explicitly expired.

    Args:
        flow_timeout: Seconds of inactivity before a flow is considered complete.
    """

    def __init__(self, flow_timeout: float = 30.0) -> None:
        self._flow_timeout = flow_timeout
        self._active_flows: dict[str, FlowRecord] = {}
        self._last_seen: dict[str, float] = {}

    @staticmethod
    def _flow_key(packet: RawPacket) -> str:
        """Generate 5-tuple key for flow grouping."""
        return f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.proto}"

    def _add_packet_to_flow(self, flow: FlowRecord, packet: RawPacket) -> None:
        """Aggregate a packet's data into an existing flow record with bounded memory footprint."""
        # Exact cumulative volume and timing metrics
        flow.packet_count += 1
        flow.total_bytes += packet.length

        # Bidirectional cross-accounting when full-duplex tap or SPAN port is monitored
        rev_key = f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}-{packet.proto}"
        rev_flow = self._active_flows.get(rev_key)
        if rev_flow is not None:
            rev_flow.reverse_bytes += packet.length
            rev_flow.reverse_packets += 1
            flow.reverse_bytes = rev_flow.total_bytes
            flow.reverse_packets = rev_flow.packet_count

        if packet.timestamp < flow.start_time or flow.start_time == 0.0:
            flow.start_time = packet.timestamp
        if packet.timestamp > flow.end_time:
            flow.end_time = packet.timestamp

        # Bounded sample lists (prevent RAM exhaustion on million-packet flows)
        if len(flow.timestamps) < MAX_FLOW_SAMPLES:
            flow.timestamps.append(packet.timestamp)
        if len(flow.packet_sizes) < MAX_FLOW_SAMPLES:
            flow.packet_sizes.append(packet.length)
        if len(flow.payload_sizes) < MAX_FLOW_SAMPLES:
            flow.payload_sizes.append(packet.payload_size)

        # TCP flags
        if packet.flags:
            if len(flow.flags_list) < MAX_FLOW_SAMPLES:
                flow.flags_list.append(packet.flags)
            if "S" in packet.flags and "A" not in packet.flags:
                flow.syn_count += 1
            if "A" in packet.flags:
                flow.ack_count += 1
            if "R" in packet.flags:
                flow.rst_count += 1
            if "F" in packet.flags:
                flow.fin_count += 1

        # DNS
        if packet.dns_query and len(flow.dns_queries) < MAX_FLOW_SAMPLES:
            flow.dns_queries.append(packet.dns_query)
        if packet.dns_qtype and len(flow.dns_qtypes) < MAX_FLOW_SAMPLES:
            flow.dns_qtypes.append(packet.dns_qtype)

        # TLS
        if packet.tls_ja3 and len(flow.tls_ja3_fingerprints) < MAX_FLOW_SAMPLES:
            flow.tls_ja3_fingerprints.append(packet.tls_ja3)

    def _create_flow(self, packet: RawPacket) -> FlowRecord:
        """Create a new FlowRecord from the first packet."""
        return FlowRecord(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            proto=packet.proto,
        )

    def process_packet(self, packet: RawPacket) -> FlowRecord | None:
        """
        Add a packet to the appropriate flow.

        Returns a completed FlowRecord if a flow timed out, else None.
        """
        key = self._flow_key(packet)
        completed: FlowRecord | None = None

        # Check for timed-out flows before processing
        if key in self._active_flows:
            last = self._last_seen[key]
            if (packet.timestamp - last) > self._flow_timeout:
                # Existing flow timed out — emit it and start new
                completed = self._active_flows.pop(key)
                del self._last_seen[key]

        # Create or update flow
        if key not in self._active_flows:
            self._active_flows[key] = self._create_flow(packet)

        self._add_packet_to_flow(self._active_flows[key], packet)
        self._last_seen[key] = packet.timestamp

        return completed

    def expire_idle_flows(self, current_time: float) -> list[FlowRecord]:
        """
        Scan and purge all flows that have been inactive longer than flow_timeout.
        Essential for streaming environments to maintain bounded RAM.
        """
        expired_keys = [
            k for k, last_t in self._last_seen.items()
            if (current_time - last_t) > self._flow_timeout
        ]
        expired_flows: list[FlowRecord] = []
        for k in expired_keys:
            expired_flows.append(self._active_flows.pop(k))
            del self._last_seen[k]

        return expired_flows

    def expire_all(self) -> list[FlowRecord]:
        """
        Purge and emit all currently active flows unconditionally.
        Clears assembler state.
        """
        return self.flush()

    def flush(self) -> list[FlowRecord]:
        """
        Emit all remaining active flows (e.g., at end of PCAP file).
        Returns list of all active flows and clears internal state.
        """
        flows = list(self._active_flows.values())
        self._active_flows.clear()
        self._last_seen.clear()
        logger.info("Flushed %d remaining flows", len(flows))
        return flows

    def assemble_from_packets(
        self, packets: Generator[RawPacket, None, None] | list[RawPacket]
    ) -> Generator[FlowRecord, None, None]:
        """
        High-level convenience: feed packets, yield completed flows.

        Args:
            packets: Iterable of RawPacket objects.

        Yields:
            FlowRecord objects as flows complete (timeout) or at end of input.
        """
        for packet in packets:
            completed = self.process_packet(packet)
            if completed is not None:
                yield completed

        # Flush remaining flows
        for flow in self.flush():
            yield flow
