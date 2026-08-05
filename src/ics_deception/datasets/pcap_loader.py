"""Streaming PCAP analysis and controlled laboratory replay.

Two clearly separated modes:

**Passive analysis (default).** The capture is read *incrementally* with
:class:`scapy.utils.PcapReader`, so memory use is independent of file size.
Bounded metadata is extracted per packet; full payloads are never logged.

**Active replay (``--replay``).** Only reached when the flag is passed
explicitly. Replay *transmits real traffic* to the configured targets and must
only ever be pointed at an isolated laboratory network. Only client-to-server
payloads are replayed, and the packet budget is bounded.
"""

from __future__ import annotations

import argparse
import contextlib
import socket
import sys
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ics_deception.common.argtypes import positive_float, positive_int
from ics_deception.common.events import EventPublisher
from ics_deception.common.modbus import (
    MAX_MBAP_LENGTH,
    MBAP_HEADER_LEN,
    MIN_MBAP_LENGTH,
    MODBUS_PROTOCOL_ID,
)
from ics_deception.common.publisher import create_event_publisher
from ics_deception.datasets.pcap_utils import parse_host_port, validate_pcap_path

__all__ = ["ReplayTargets", "Summary", "analyse_capture", "main"]

MODBUS_PORT = 502
DNP3_PORT = 20000

DEFAULT_MAX_PACKETS = 5000
DEFAULT_REPLAY_TIMEOUT = 2.0

#: Bytes of payload recorded per packet event (hex-encoded).
MAX_SAMPLE_BYTES = 32


class ScapyUnavailableError(RuntimeError):
    """Scapy is required for capture processing but is not installed."""


def _import_scapy():
    """Import Scapy lazily so the rest of the package works without it."""
    try:
        from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
        from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
        from scapy.packet import Raw  # type: ignore[import-untyped]
        from scapy.utils import PcapReader  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ScapyUnavailableError(
            "scapy is required for PCAP processing; install with: pip install 'ics-deception[pcap]'"
        ) from exc
    return PcapReader, IP, IPv6, TCP, Raw


@dataclass
class ReplayTargets:
    """Explicit laboratory destinations for replayed traffic."""

    modbus_host: str = "127.0.0.1"
    modbus_port: int = 5020
    dnp3_host: str = "127.0.0.1"
    dnp3_port: int = 20000


@dataclass
class Summary:
    """Counters describing one analysis run."""

    packets_seen: int = 0
    packets_matched: int = 0
    packets_replayed: int = 0
    errors: int = 0
    by_protocol: dict[str, int] = field(default_factory=lambda: {"modbus": 0, "dnp3": 0})

    def as_dict(self) -> dict:
        """Return the counters as a plain dictionary."""
        return asdict(self)


def _endpoints(packet, IP, IPv6) -> tuple[str, str] | None:
    """Extract source/destination addresses, supporting IPv4 and IPv6."""
    if packet.haslayer(IP):
        layer = packet[IP]
        return str(layer.src), str(layer.dst)
    if packet.haslayer(IPv6):
        layer = packet[IPv6]
        return str(layer.src), str(layer.dst)
    return None


def _parse_modbus(payload: bytes) -> dict | None:
    """Validate the MBAP header and return bounded metadata, or ``None``."""
    if len(payload) < MBAP_HEADER_LEN + 1:
        return None
    protocol_id = int.from_bytes(payload[2:4], "big")
    if protocol_id != MODBUS_PROTOCOL_ID:
        return None
    length = int.from_bytes(payload[4:6], "big")
    # The MBAP length counts the unit id plus the PDU, so its maximum is 254,
    # not 253. The shared bounds keep this identical to the Python and C++
    # servers; a local constant here previously rejected valid maximum-size
    # frames as unparseable.
    if not MIN_MBAP_LENGTH <= length <= MAX_MBAP_LENGTH:
        return None
    return {
        "transaction_id": int.from_bytes(payload[0:2], "big"),
        "protocol_id": protocol_id,
        "mbap_length": length,
        "unit_id": payload[6],
        "function_code": payload[7],
        "payload_len": len(payload),
        "length_consistent": len(payload) >= MBAP_HEADER_LEN - 1 + length,
    }


def _parse_dnp3(payload: bytes) -> dict | None:
    """Return bounded metadata for a DNP3-looking payload."""
    if len(payload) < 2:
        return None
    return {
        "payload_len": len(payload),
        "link_start": payload[:2].hex(),
        "looks_like_dnp3": payload[:2] == b"\x05\x64",
        "hex_sample": payload[:MAX_SAMPLE_BYTES].hex(),
    }


def _replay(payload: bytes, host: str, port: int, timeout: float) -> None:
    """Send one payload to a laboratory target and read at most one reply."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        # A missing, slow or reset reply is not a replay failure.
        with contextlib.suppress(OSError):
            sock.recv(4096)


def analyse_capture(
    pcap_path: Path,
    publisher: EventPublisher,
    replay: bool = False,
    targets: ReplayTargets | None = None,
    max_packets: int = DEFAULT_MAX_PACKETS,
    replay_timeout: float = DEFAULT_REPLAY_TIMEOUT,
) -> Summary:
    """Stream a capture, emit per-packet metadata events and return counters.

    Individual replay failures are logged and counted; they never abort the
    analysis of the remaining packets.
    """
    PcapReader, IP, IPv6, TCP, Raw = _import_scapy()
    targets = targets if targets is not None else ReplayTargets()
    summary = Summary()

    publisher.emit(
        "pcap_analysis_started",
        pcap=str(pcap_path),
        replay=replay,
        max_packets=max_packets,
        modbus_target=f"{targets.modbus_host}:{targets.modbus_port}" if replay else None,
        dnp3_target=f"{targets.dnp3_host}:{targets.dnp3_port}" if replay else None,
    )

    reader: Iterator = PcapReader(str(pcap_path))
    try:
        for packet in reader:
            if summary.packets_seen >= max_packets:
                publisher.emit(
                    "pcap_packet_limit_reached",
                    limit=max_packets,
                    pcap=str(pcap_path),
                )
                break
            summary.packets_seen += 1

            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                continue
            tcp = packet[TCP]
            addresses = _endpoints(packet, IP, IPv6)
            if addresses is None:
                continue
            src, dst = addresses
            payload = bytes(packet[Raw].load)

            is_modbus = MODBUS_PORT in (tcp.dport, tcp.sport)
            is_dnp3 = DNP3_PORT in (tcp.dport, tcp.sport)
            if not (is_modbus or is_dnp3):
                continue

            protocol = "modbus" if is_modbus else "dnp3"
            service_port = MODBUS_PORT if is_modbus else DNP3_PORT
            # Only client-to-server frames are candidates for replay.
            client_to_server = int(tcp.dport) == service_port

            metadata = (
                _parse_modbus(payload) if is_modbus else _parse_dnp3(payload)
            )
            if metadata is None:
                continue

            summary.packets_matched += 1
            summary.by_protocol[protocol] += 1
            publisher.emit(
                f"{protocol}_packet",
                src=f"{src}:{tcp.sport}",
                dst=f"{dst}:{tcp.dport}",
                direction="client_to_server" if client_to_server else "server_to_client",
                **metadata,
            )

            if not (replay and client_to_server):
                continue
            host = targets.modbus_host if is_modbus else targets.dnp3_host
            port = targets.modbus_port if is_modbus else targets.dnp3_port
            try:
                _replay(payload, host, port, replay_timeout)
                summary.packets_replayed += 1
                publisher.emit(
                    f"{protocol}_replayed", target=f"{host}:{port}", bytes_sent=len(payload)
                )
            except OSError as exc:
                summary.errors += 1
                publisher.emit(
                    f"{protocol}_replay_error", target=f"{host}:{port}", error=str(exc)
                )
    finally:
        close = getattr(reader, "close", None)
        if callable(close):
            close()

    publisher.emit("pcap_analysis_finished", pcap=str(pcap_path), **summary.as_dict())
    return summary


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ics-pcap",
        description=(
            "Passive Modbus/DNP3 capture analysis, with optional controlled replay. "
            "Replay transmits real traffic and is for isolated laboratory networks only."
        ),
    )
    parser.add_argument("--pcap", required=True, help="capture file (.pcap or .pcapng)")
    parser.add_argument(
        "--approved-dir",
        default=None,
        help="approved capture directory (default: ICS_DECEPTION_PCAP_DIR or ./data/pcaps)",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="TRANSMIT client-to-server payloads to the configured laboratory targets",
    )
    parser.add_argument(
        "--modbus-target",
        default="127.0.0.1:5020",
        help="replay destination for Modbus traffic (HOST[:PORT])",
    )
    parser.add_argument(
        "--dnp3-target",
        default="127.0.0.1:20000",
        help="replay destination for DNP3 traffic (HOST[:PORT])",
    )
    parser.add_argument(
        "--max-packets",
        type=positive_int,
        default=DEFAULT_MAX_PACKETS,
        help=f"maximum packets to process, must be > 0 (default: {DEFAULT_MAX_PACKETS})",
    )
    parser.add_argument(
        "--replay-timeout",
        type=positive_float,
        default=DEFAULT_REPLAY_TIMEOUT,
        help="replay socket timeout in seconds, must be > 0",
    )
    parser.add_argument("--log", default=None, help="JSONL event log path override")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for ``ics-pcap``."""
    from ics_deception.common.paths import pcap_dir  # local import: keeps CLI startup cheap

    args = _parse_args(argv)
    publisher = create_event_publisher(source="pcap_loader", log_path=args.log)
    approved = Path(args.approved_dir).expanduser().resolve() if args.approved_dir else pcap_dir()

    try:
        pcap_path = validate_pcap_path(args.pcap, approved)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    modbus_host, modbus_port = parse_host_port(args.modbus_target, 5020)
    dnp3_host, dnp3_port = parse_host_port(args.dnp3_target, 20000)
    targets = ReplayTargets(
        modbus_host=modbus_host,
        modbus_port=modbus_port,
        dnp3_host=dnp3_host,
        dnp3_port=dnp3_port,
    )

    if args.replay:
        print(
            "WARNING: --replay transmits real traffic to "
            f"{modbus_host}:{modbus_port} (Modbus) and {dnp3_host}:{dnp3_port} (DNP3). "
            "Use only on an isolated laboratory network.",
            file=sys.stderr,
        )

    try:
        summary = analyse_capture(
            pcap_path=pcap_path,
            publisher=publisher,
            replay=args.replay,
            targets=targets,
            max_packets=args.max_packets,
            replay_timeout=args.replay_timeout,
        )
    except ScapyUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    print(
        "packets_seen={packets_seen} packets_matched={packets_matched} "
        "packets_replayed={packets_replayed} errors={errors}".format(**summary.as_dict())
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
