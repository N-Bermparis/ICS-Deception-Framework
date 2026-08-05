"""Standard-library Modbus/TCP deception server.

A small, dependency-free Modbus/TCP server used for quick demonstrations and
for unit tests. The production-grade sensor for laboratory deployments is the
native C++ honeypot in ``src/native/modbus_honeypot.cpp``; this module trades
features for portability.

Scope — implemented deliberately as a *subset*:

* FC03 — Read Holding Registers
* FC06 — Write Single Register
* Correct MBAP length parsing and TCP stream reassembly
* Modbus exception responses for everything else
* Structured JSONL event logging

This is **not** a standards-compliant Modbus device. Diagnostics, file record
access, serial gateway behaviour and exception subtleties are not modelled.
"""

from __future__ import annotations

import argparse
import socketserver
import sys
import threading
from collections.abc import Sequence

from ics_deception.common.argtypes import bounded_int, port_number, positive_float
from ics_deception.common.events import EventPublisher
from ics_deception.common.modbus import (
    EXC_ILLEGAL_DATA_ADDRESS,
    EXC_ILLEGAL_DATA_VALUE,
    EXC_ILLEGAL_FUNCTION,
    FC_READ_HOLDING_REGISTERS,
    FC_WRITE_SINGLE_REGISTER,
    MAX_ADU_LEN,
    MAX_MBAP_LENGTH,
    MBAP_HEADER_LEN,
    MIN_MBAP_LENGTH,
    MODBUS_PROTOCOL_ID,
    build_exception_response,
    build_response,
    parse_mbap,
)
from ics_deception.common.publisher import create_event_publisher

__all__ = ["ModbusDeceptionServer", "RegisterBank", "main"]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5020
DEFAULT_REGISTERS = 256
DEFAULT_TIMEOUT = 30.0

#: Hard cap on buffered bytes per connection before the peer is disconnected.
MAX_BUFFER = 4 * MAX_ADU_LEN


class RegisterBank:
    """Thread-safe holding-register store with a simulated critical range."""

    def __init__(
        self,
        size: int = DEFAULT_REGISTERS,
        critical_start: int = 100,
        critical_end: int = 110,
    ) -> None:
        self.size = size
        self.critical_start = critical_start
        self.critical_end = critical_end
        self._registers = [0] * size
        self._lock = threading.Lock()

    def is_critical(self, address: int) -> bool:
        """Return whether ``address`` falls inside the simulated critical range."""
        return self.critical_start <= address <= self.critical_end

    def read(self, address: int, quantity: int) -> list[int]:
        """Read ``quantity`` registers starting at ``address``."""
        with self._lock:
            return self._registers[address : address + quantity]

    def write(self, address: int, value: int) -> None:
        """Write a single register."""
        with self._lock:
            self._registers[address] = value & 0xFFFF

    def snapshot(self) -> list[int]:
        """Return a copy of the whole register file."""
        with self._lock:
            return list(self._registers)


class _Handler(socketserver.BaseRequestHandler):
    """Per-connection handler performing MBAP-aware stream reassembly."""

    server: ModbusDeceptionServer  # narrowed for type checkers

    def handle(self) -> None:  # noqa: C901 - protocol dispatch is inherently branchy
        server = self.server
        publisher = server.publisher
        peer_ip, peer_port = self.client_address[0], self.client_address[1]
        publisher.emit("modbus_connection", client_ip=peer_ip, client_port=peer_port)
        self.request.settimeout(server.client_timeout)

        buffer = bytearray()
        try:
            while not server.stopping:
                try:
                    chunk = self.request.recv(4096)
                except TimeoutError:
                    # socket.timeout is an alias of TimeoutError on Python 3.10+.
                    publisher.emit(
                        "modbus_timeout", client_ip=peer_ip, client_port=peer_port
                    )
                    break
                except OSError as exc:
                    publisher.emit(
                        "modbus_connection_error",
                        client_ip=peer_ip,
                        client_port=peer_port,
                        error=str(exc),
                    )
                    break
                if not chunk:
                    break

                buffer.extend(chunk)
                if len(buffer) > MAX_BUFFER:
                    publisher.emit(
                        "modbus_malformed",
                        client_ip=peer_ip,
                        client_port=peer_port,
                        reason="buffer_overflow",
                        buffered=len(buffer),
                    )
                    break

                # Drain every complete frame currently in the buffer.
                while True:
                    header = parse_mbap(bytes(buffer))
                    if header is None:
                        break  # fewer than 7 bytes: wait for more data

                    if header.protocol_id != MODBUS_PROTOCOL_ID:
                        publisher.emit(
                            "modbus_malformed",
                            client_ip=peer_ip,
                            client_port=peer_port,
                            reason="bad_protocol_id",
                            protocol_id=header.protocol_id,
                        )
                        buffer.clear()
                        return
                    if not MIN_MBAP_LENGTH <= header.length <= MAX_MBAP_LENGTH:
                        publisher.emit(
                            "modbus_malformed",
                            client_ip=peer_ip,
                            client_port=peer_port,
                            reason="bad_mbap_length",
                            length=header.length,
                        )
                        buffer.clear()
                        return
                    if len(buffer) < header.total_frame_len:
                        break  # partial frame: wait for the remaining bytes

                    frame = bytes(buffer[: header.total_frame_len])
                    del buffer[: header.total_frame_len]
                    pdu = frame[MBAP_HEADER_LEN:]

                    publisher.emit(
                        "modbus_request",
                        client_ip=peer_ip,
                        client_port=peer_port,
                        unit_id=header.unit_id,
                        function_code=pdu[0],
                        bytes_in=len(frame),
                    )
                    response = server.dispatch(header, pdu, peer_ip, peer_port)
                    self._send_all(response)
                    publisher.emit(
                        "modbus_response",
                        client_ip=peer_ip,
                        client_port=peer_port,
                        unit_id=header.unit_id,
                        function_code=response[MBAP_HEADER_LEN],
                        bytes_out=len(response),
                    )
        finally:
            publisher.emit(
                "modbus_connection_closed", client_ip=peer_ip, client_port=peer_port
            )

    def _send_all(self, payload: bytes) -> None:
        """Send the whole payload, tolerating short writes."""
        view = memoryview(payload)
        while view:
            sent = self.request.send(view)
            if sent <= 0:
                raise OSError("short write on Modbus response")
            view = view[sent:]


class ModbusDeceptionServer(socketserver.ThreadingTCPServer):
    """Threaded Modbus/TCP deception server bound to loopback by default."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        bank: RegisterBank | None = None,
        publisher: EventPublisher | None = None,
        client_timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.bank = bank if bank is not None else RegisterBank()
        self.publisher = (
            publisher
            if publisher is not None
            else create_event_publisher(source="modbus_server")
        )
        self.client_timeout = client_timeout
        self.stopping = False
        super().__init__((host, port), _Handler)

    @property
    def port(self) -> int:
        """Actual bound port (useful when binding to port 0 in tests)."""
        return int(self.server_address[1])

    @property
    def host(self) -> str:
        """Actual bound address."""
        return str(self.server_address[0])

    def dispatch(
        self, header, pdu: bytes, peer_ip: str, peer_port: int
    ) -> bytes:
        """Route a PDU to its handler and return a complete response ADU."""
        function_code = pdu[0]
        if function_code == FC_READ_HOLDING_REGISTERS:
            return self._read_holding_registers(header, pdu)
        if function_code == FC_WRITE_SINGLE_REGISTER:
            return self._write_single_register(header, pdu, peer_ip, peer_port)
        self.publisher.emit(
            "modbus_unsupported_function",
            client_ip=peer_ip,
            client_port=peer_port,
            function_code=function_code,
        )
        return build_exception_response(
            header.transaction_id, header.unit_id, function_code, EXC_ILLEGAL_FUNCTION
        )

    def _read_holding_registers(self, header, pdu: bytes) -> bytes:
        if len(pdu) != 5:
            return build_exception_response(
                header.transaction_id,
                header.unit_id,
                FC_READ_HOLDING_REGISTERS,
                EXC_ILLEGAL_DATA_VALUE,
            )
        address = int.from_bytes(pdu[1:3], "big")
        quantity = int.from_bytes(pdu[3:5], "big")
        if quantity == 0 or quantity > 125:
            return build_exception_response(
                header.transaction_id,
                header.unit_id,
                FC_READ_HOLDING_REGISTERS,
                EXC_ILLEGAL_DATA_VALUE,
            )
        if address + quantity > self.bank.size:
            return build_exception_response(
                header.transaction_id,
                header.unit_id,
                FC_READ_HOLDING_REGISTERS,
                EXC_ILLEGAL_DATA_ADDRESS,
            )
        values = self.bank.read(address, quantity)
        payload = b"".join(value.to_bytes(2, "big") for value in values)
        response_pdu = bytes([FC_READ_HOLDING_REGISTERS, len(payload)]) + payload
        return build_response(header.transaction_id, header.unit_id, response_pdu)

    def _write_single_register(
        self, header, pdu: bytes, peer_ip: str, peer_port: int
    ) -> bytes:
        if len(pdu) != 5:
            return build_exception_response(
                header.transaction_id,
                header.unit_id,
                FC_WRITE_SINGLE_REGISTER,
                EXC_ILLEGAL_DATA_VALUE,
            )
        address = int.from_bytes(pdu[1:3], "big")
        value = int.from_bytes(pdu[3:5], "big")
        if address >= self.bank.size:
            return build_exception_response(
                header.transaction_id,
                header.unit_id,
                FC_WRITE_SINGLE_REGISTER,
                EXC_ILLEGAL_DATA_ADDRESS,
            )
        self.bank.write(address, value)
        if self.bank.is_critical(address):
            self.publisher.emit(
                "sabotage_detected",
                client_ip=peer_ip,
                client_port=peer_port,
                function_code=FC_WRITE_SINGLE_REGISTER,
                address=address,
                value=value,
                alert="write_to_critical_register",
            )
        # A successful FC06 echoes address and value back to the client.
        return build_response(header.transaction_id, header.unit_id, pdu)

    def shutdown(self) -> None:
        """Stop the serving loop and mark handlers for termination."""
        self.stopping = True
        super().shutdown()


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ics-modbus-server",
        description=(
            "Standard-library Modbus/TCP deception server (FC03/FC06 subset). "
            "Authorized laboratory research use only."
        ),
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address (default: loopback)")
    parser.add_argument(
        "--port", type=port_number, default=DEFAULT_PORT, help="TCP port 1..65535 (default: 5020)"
    )
    parser.add_argument(
        "--registers",
        type=bounded_int(1, 65536),
        default=DEFAULT_REGISTERS,
        help="holding register count, must be > 0",
    )
    parser.add_argument(
        "--crit-start", type=bounded_int(0, 0xFFFF), default=100, help="critical range start"
    )
    parser.add_argument(
        "--crit-end", type=bounded_int(0, 0xFFFF), default=110, help="critical range end"
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
    """CLI entry point for ``ics-modbus-server``."""
    args = _parse_args(argv)
    if args.crit_start > args.crit_end:
        print("error: --crit-start must not exceed --crit-end", file=sys.stderr)
        return 2
    publisher = create_event_publisher(source="modbus_server", log_path=args.log)
    bank = RegisterBank(
        size=args.registers, critical_start=args.crit_start, critical_end=args.crit_end
    )
    server = ModbusDeceptionServer(
        host=args.host,
        port=args.port,
        bank=bank,
        publisher=publisher,
        client_timeout=args.timeout,
    )
    publisher.emit("modbus_server_startup", host=server.host, port=server.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        publisher.emit("modbus_server_shutdown", host=server.host, port=server.port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
