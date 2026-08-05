"""Fake PLC node.

Periodically polls the Modbus honeypot with a **valid FC03 (Read Holding
Registers) request** — the previous prototype sent the literal string
``HEARTBEAT``, which is not Modbus and made the honeypot log malformed frames.

The most recent poll result is written to a state file that the controller
serves through ``GET /ics-values``. The write is atomic (write to a temporary
file in the same directory, then ``os.replace``) so the controller can never
observe a half-written JSON document.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

from ics_deception.common.argtypes import bounded_int, port_number, positive_float
from ics_deception.common.modbus import (
    MBAP_HEADER_LEN,
    MODBUS_PROTOCOL_ID,
    build_read_holding_registers_request,
    parse_mbap,
)
from ics_deception.common.paths import ensure_dir, plc_state_path
from ics_deception.common.publisher import create_event_publisher

__all__ = ["poll_once", "write_state_atomically", "main"]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5020
DEFAULT_INTERVAL = 10.0
DEFAULT_TIMEOUT = 3.0
DEFAULT_ADDRESS = 0
DEFAULT_QUANTITY = 8


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly ``count`` bytes or raise ``OSError`` on premature EOF."""
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("connection closed while reading Modbus response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def poll_once(
    host: str,
    port: int,
    unit_id: int = 1,
    address: int = DEFAULT_ADDRESS,
    quantity: int = DEFAULT_QUANTITY,
    timeout: float = DEFAULT_TIMEOUT,
    transaction_id: int = 1,
) -> dict:
    """Perform one FC03 read and return a structured result.

    Raises ``OSError`` on connection problems and ``ValueError`` on a response
    that is not a well-formed Modbus/TCP ADU.
    """
    request = build_read_holding_registers_request(transaction_id, unit_id, address, quantity)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        header_bytes = _recv_exact(sock, MBAP_HEADER_LEN)
        header = parse_mbap(header_bytes)
        if header is None or header.protocol_id != MODBUS_PROTOCOL_ID:
            raise ValueError("invalid MBAP header in response")
        if header.length < 2:
            raise ValueError(f"invalid MBAP length in response: {header.length}")
        pdu = _recv_exact(sock, header.pdu_len)

    function_code = pdu[0]
    if function_code & 0x80:
        return {
            "ok": False,
            "function_code": function_code & 0x7F,
            "exception_code": pdu[1] if len(pdu) > 1 else None,
            "registers": [],
        }
    if function_code != 0x03 or len(pdu) < 2:
        raise ValueError(f"unexpected response function code: {function_code}")
    byte_count = pdu[1]
    data = pdu[2 : 2 + byte_count]
    if len(data) != byte_count:
        raise ValueError("truncated register payload in response")
    registers = [int.from_bytes(data[i : i + 2], "big") for i in range(0, byte_count, 2)]
    return {
        "ok": True,
        "function_code": function_code,
        "exception_code": None,
        "registers": registers,
    }


def write_state_atomically(state: dict, path: Path) -> None:
    """Write ``state`` as JSON to ``path`` atomically.

    A temporary file is created in the *same* directory so that ``os.replace``
    is a same-filesystem rename, which is atomic on POSIX and on Windows.
    """
    ensure_dir(path.parent)
    # Not a context manager here: delete=False plus an explicit os.replace is
    # what makes the swap atomic, and the name is needed after closing.
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    tmp_name = handle.name
    try:
        with handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        # Never leave a stray temporary file behind on failure.
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ics-fake-plc",
        description=(
            "Fake PLC node that polls the Modbus honeypot with valid FC03 "
            "requests and publishes its last reading. Laboratory use only."
        ),
    )
    parser.add_argument(
        "--target-host", default=DEFAULT_HOST, help="Modbus honeypot host (default: loopback)"
    )
    parser.add_argument(
        "--target-port",
        type=port_number,
        default=DEFAULT_PORT,
        help="Modbus honeypot port 1..65535 (default: 5020)",
    )
    parser.add_argument(
        "--unit-id", type=bounded_int(0, 255), default=1, help="Modbus unit identifier 0..255"
    )
    parser.add_argument(
        "--address", type=bounded_int(0, 0xFFFF), default=DEFAULT_ADDRESS, help="start register"
    )
    parser.add_argument(
        "--quantity",
        type=bounded_int(1, 125),
        default=DEFAULT_QUANTITY,
        help="register count 1..125 (Modbus FC03 limit)",
    )
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=DEFAULT_INTERVAL,
        help="seconds between polls, must be > 0",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=DEFAULT_TIMEOUT,
        help="socket timeout in seconds, must be > 0",
    )
    parser.add_argument("--once", action="store_true", help="poll a single time and exit")
    parser.add_argument("--state-file", default=None, help="PLC state file path override")
    parser.add_argument("--log", default=None, help="JSONL event log path override")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for ``ics-fake-plc``."""
    args = _parse_args(argv)
    publisher = create_event_publisher(source="fake_plc", log_path=args.log)
    state_file = Path(args.state_file) if args.state_file else plc_state_path()

    publisher.emit(
        "fake_plc_startup",
        target_host=args.target_host,
        target_port=args.target_port,
        interval=args.interval,
        state_file=str(state_file),
    )

    transaction_id = 0
    exit_code = 0
    while True:
        transaction_id = (transaction_id + 1) % 0xFFFF or 1
        state: dict = {
            "timestamp": None,
            "target": f"{args.target_host}:{args.target_port}",
            "unit_id": args.unit_id,
            "address": args.address,
            "quantity": args.quantity,
        }
        try:
            result = poll_once(
                host=args.target_host,
                port=args.target_port,
                unit_id=args.unit_id,
                address=args.address,
                quantity=args.quantity,
                timeout=args.timeout,
                transaction_id=transaction_id,
            )
            state.update(result)
            state["error"] = None
            event = publisher.emit(
                "fake_plc_poll",
                target=state["target"],
                ok=result["ok"],
                registers=result["registers"],
            )
            exit_code = 0
        except (OSError, ValueError) as exc:
            state.update({"ok": False, "registers": [], "error": str(exc)})
            event = publisher.emit(
                "fake_plc_poll_failed", target=state["target"], error=str(exc)
            )
            exit_code = 1
        state["timestamp"] = event.timestamp

        try:
            write_state_atomically(state, state_file)
        except OSError as exc:  # pragma: no cover - disk/permission failure
            publisher.error("fake_plc_state_write_failed", error=str(exc))

        if args.once:
            return exit_code
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:  # pragma: no cover - interactive only
            publisher.emit("fake_plc_shutdown")
            return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
