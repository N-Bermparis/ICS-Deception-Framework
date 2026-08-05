"""DNP3-inspired interaction sensor.

.. warning::

   This is **not** a DNP3 outstation and does not implement the DNP3 protocol.
   There is no link-layer CRC validation, no transport-function segmentation,
   no application-layer object parsing, no data-link confirmation and no
   secure authentication. A real DNP3 master will not interoperate with it.

What it *does* do is listen on the DNP3 registered port, accept connections,
emit a plausible-looking link-layer start sequence, and record bounded samples
of whatever a peer sends. That makes it useful as an *interaction sensor*: it
tells you that something scanned or probed the port, and roughly what it sent.
"""

from __future__ import annotations

import argparse
import socketserver
import sys
import threading
from collections.abc import Sequence

from ics_deception.common.argtypes import port_number, positive_float
from ics_deception.common.events import EventPublisher
from ics_deception.common.publisher import create_event_publisher

__all__ = ["Dnp3InteractionSensor", "main"]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 20000
DEFAULT_TIMEOUT = 20.0

#: DNP3 link-layer frames start with 0x0564. Emitting it makes the service look
#: plausible to a scanner without claiming any protocol conformance.
LINK_START = b"\x05\x64"

#: Maximum bytes accepted from a single peer before the session is closed.
MAX_SESSION_BYTES = 64 * 1024
#: Maximum bytes of payload recorded per event (hex-encoded in the log).
MAX_SAMPLE_BYTES = 32


class _Handler(socketserver.BaseRequestHandler):
    server: Dnp3InteractionSensor

    def handle(self) -> None:
        server = self.server
        publisher = server.publisher
        peer_ip, peer_port = self.client_address[0], self.client_address[1]
        publisher.emit("dnp3_connection", client_ip=peer_ip, client_port=peer_port)
        self.request.settimeout(server.client_timeout)

        session_bytes = 0
        try:
            self._send_all(LINK_START + b"\x05\xc4\x01\x02\x03\x04")
            while not server.stopping:
                try:
                    data = self.request.recv(4096)
                except TimeoutError:
                    publisher.emit("dnp3_timeout", client_ip=peer_ip, client_port=peer_port)
                    break
                except OSError as exc:
                    publisher.emit(
                        "dnp3_connection_error",
                        client_ip=peer_ip,
                        client_port=peer_port,
                        error=str(exc),
                    )
                    break
                if not data:
                    break

                session_bytes += len(data)
                publisher.emit(
                    "dnp3_interaction",
                    client_ip=peer_ip,
                    client_port=peer_port,
                    length=len(data),
                    session_bytes=session_bytes,
                    # Only a bounded prefix is recorded; never the full payload.
                    hex_sample=data[:MAX_SAMPLE_BYTES].hex(),
                    truncated=len(data) > MAX_SAMPLE_BYTES,
                )
                if session_bytes > MAX_SESSION_BYTES:
                    publisher.emit(
                        "dnp3_session_limit",
                        client_ip=peer_ip,
                        client_port=peer_port,
                        session_bytes=session_bytes,
                    )
                    break

                # Static, non-conformant acknowledgement-shaped reply.
                self._send_all(LINK_START + b"\x0b\x44" + data[:4])
        except OSError as exc:
            publisher.emit(
                "dnp3_connection_error",
                client_ip=peer_ip,
                client_port=peer_port,
                error=str(exc),
            )
        finally:
            publisher.emit(
                "dnp3_connection_closed",
                client_ip=peer_ip,
                client_port=peer_port,
                session_bytes=session_bytes,
            )

    def _send_all(self, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            sent = self.request.send(view)
            if sent <= 0:
                raise OSError("short write on DNP3 reply")
            view = view[sent:]


class Dnp3InteractionSensor(socketserver.ThreadingTCPServer):
    """Threaded TCP sensor on the DNP3 port. One thread per client."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        publisher: EventPublisher | None = None,
        client_timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.publisher = (
            publisher
            if publisher is not None
            else create_event_publisher(source="dnp3_sensor")
        )
        self.client_timeout = client_timeout
        self.stopping = False
        self._lock = threading.Lock()
        super().__init__((host, port), _Handler)

    @property
    def port(self) -> int:
        """Actual bound port."""
        return int(self.server_address[1])

    @property
    def host(self) -> str:
        """Actual bound address."""
        return str(self.server_address[0])

    def shutdown(self) -> None:
        """Stop the serving loop and mark handlers for termination."""
        self.stopping = True
        super().shutdown()


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ics-dnp3-sensor",
        description=(
            "DNP3-inspired interaction sensor. NOT a DNP3 outstation and not "
            "standards compliant. Authorized laboratory research use only."
        ),
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address (default: loopback)")
    parser.add_argument(
        "--port", type=port_number, default=DEFAULT_PORT, help="TCP port 1..65535 (default: 20000)"
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=DEFAULT_TIMEOUT,
        help="per-client receive timeout in seconds, must be > 0",
    )
    parser.add_argument("--log", default=None, help="JSONL event log path override")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for ``ics-dnp3-sensor``."""
    args = _parse_args(argv)
    publisher = create_event_publisher(source="dnp3_sensor", log_path=args.log)
    sensor = Dnp3InteractionSensor(
        host=args.host, port=args.port, publisher=publisher, client_timeout=args.timeout
    )
    publisher.emit(
        "dnp3_sensor_startup",
        host=sensor.host,
        port=sensor.port,
        note="DNP3-inspired interaction sensor; not a protocol implementation",
    )
    try:
        sensor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        sensor.shutdown()
        sensor.server_close()
        publisher.emit("dnp3_sensor_shutdown", host=sensor.host, port=sensor.port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
