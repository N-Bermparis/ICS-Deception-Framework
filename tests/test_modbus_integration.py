"""Integration test for the native C++ Modbus honeypot.

The full round trip against the real binary:

1. Build or locate ``modbus_honeypot``.
2. Pick a free unprivileged port.
3. Start the honeypot on loopback with a deterministic seed and no error injection.
4. Send an FC03 request split across several TCP writes.
5. Confirm the split request was reassembled and answered correctly.
6. Write to a simulated critical register with FC06.
7. Read the value back with FC03.
8. Confirm the value round-tripped.
9. Stop the process.
10. Confirm a ``sabotage_detected`` event reached the JSONL log.

The test is skipped (never failed) when no C++ toolchain is available, so the
Python suite still runs on platforms without ``make``/``g++``.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path

import pytest

from ics_deception.common.modbus import (
    MBAP_HEADER_LEN,
    build_read_holding_registers_request,
    build_write_single_register_request,
    parse_mbap,
)
from tests.conftest import free_tcp_port

pytestmark = pytest.mark.integration

CRITICAL_REGISTER = 105
CRITICAL_VALUE = 0xC0DE
STARTUP_TIMEOUT = 10.0


@pytest.fixture
def modbus_binary(native_build: Path) -> Path:
    """The freshly compiled honeypot from the session build fixture.

    Deliberately not a prebuilt ``build/modbus_honeypot`` from the working tree:
    a stale binary would make this integration test pass against old sources.
    """
    candidate = native_build / "modbus_honeypot"
    if not candidate.is_file():  # pragma: no cover - the build fixture would have failed
        pytest.skip("modbus_honeypot was not produced by the native build")
    return candidate


@pytest.fixture
def honeypot(modbus_binary, tmp_path):
    """Start the honeypot on a free loopback port and yield (port, log_path)."""
    port = free_tcp_port()
    # Deliberately nested under directories that do not exist yet: the native
    # logger must create them rather than silently dropping every event.
    log_path = tmp_path / "runtime" / "native" / "modbus_honeypot.jsonl"
    stdout_path = tmp_path / "honeypot.out"

    with open(stdout_path, "wb") as stdout_handle:
        process = subprocess.Popen(
            [
                str(modbus_binary),
                "--bind",
                "127.0.0.1",
                "--port",
                str(port),
                "--error-percent",
                "0",  # deterministic: never inject random failures
                "--seed",
                "1",
                "--max-clients",
                "8",
                "--crit-start",
                "100",
                "--crit-end",
                "110",
                "--timeout",
                "5",
                "--log",
                str(log_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=subprocess.STDOUT,
        )

        try:
            _wait_until_listening(process, port, stdout_path)
            yield port, log_path
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    process.kill()
                    process.wait(timeout=5)


def _wait_until_listening(process: subprocess.Popen, port: int, stdout_path: Path) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = stdout_path.read_text(encoding="utf-8", errors="replace")
            pytest.fail(f"honeypot exited early (code {process.returncode}):\n{output}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    process.terminate()
    pytest.fail(f"honeypot did not start listening on port {port} within {STARTUP_TIMEOUT}s")


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        assert chunk, "connection closed before the full response arrived"
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_response(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, MBAP_HEADER_LEN)
    parsed = parse_mbap(header)
    assert parsed is not None
    return header + _recv_exact(sock, parsed.pdu_len)


def _read_log(log_path: Path) -> list[dict]:
    if not log_path.is_file():
        return []
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_split_frame_write_and_readback_and_sabotage_alert(honeypot):
    port, log_path = honeypot

    # 4-5. An FC03 request delivered one byte at a time must be reassembled.
    split_request = build_read_holding_registers_request(0x0101, 1, 0, 2)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        for index in range(len(split_request)):
            sock.sendall(split_request[index : index + 1])
            time.sleep(0.01)  # force separate TCP segments
        response = _read_response(sock)

    header = parse_mbap(response)
    assert header.transaction_id == 0x0101, "transaction id lost across the split frame"
    assert header.protocol_id == 0
    pdu = response[MBAP_HEADER_LEN:]
    assert pdu[0] == 0x03, "split request was not reassembled into a valid FC03"
    assert pdu[1] == 4, "unexpected byte count for a 2-register read"
    assert len(response) == header.total_frame_len

    # 6-8. Write a critical register with FC06, then read it back with FC03.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        write_request = build_write_single_register_request(
            0x0202, 1, CRITICAL_REGISTER, CRITICAL_VALUE
        )
        sock.sendall(write_request)
        write_response = _read_response(sock)
        assert write_response == write_request, "FC06 must echo the request on success"

        sock.sendall(build_read_holding_registers_request(0x0303, 1, CRITICAL_REGISTER, 1))
        read_response = _read_response(sock)

    read_pdu = read_response[MBAP_HEADER_LEN:]
    assert read_pdu[0] == 0x03
    assert read_pdu[1] == 2
    assert int.from_bytes(read_pdu[2:4], "big") == CRITICAL_VALUE, "register value did not persist"

    # 9-10. Stop the process, then confirm the alert reached the JSONL log.
    process_stopped_log = _wait_for_event(log_path, "sabotage_detected")
    assert process_stopped_log["details"]["address"] == CRITICAL_REGISTER
    assert process_stopped_log["details"]["alert"] == "write_to_critical_register"
    assert process_stopped_log["details"]["function_code"] == 0x06
    assert process_stopped_log["source"] == "modbus_honeypot"


def _wait_for_event(log_path: Path, event_type: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = [r for r in _read_log(log_path) if r.get("event_type") == event_type]
        if matches:
            return matches[0]
        time.sleep(0.1)
    seen = sorted({r.get("event_type", "?") for r in _read_log(log_path)})
    pytest.fail(f"no {event_type!r} event within {timeout}s; observed: {seen}")


def test_pipelined_requests_in_one_segment_are_all_answered(honeypot):
    port, _ = honeypot
    pipelined = build_write_single_register_request(1, 1, 7, 0xAAAA) + (
        build_read_holding_registers_request(2, 1, 7, 1)
    )

    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(pipelined)
        first = _read_response(sock)
        second = _read_response(sock)

    assert parse_mbap(first).transaction_id == 1
    assert parse_mbap(second).transaction_id == 2
    assert int.from_bytes(second[MBAP_HEADER_LEN + 2 : MBAP_HEADER_LEN + 4], "big") == 0xAAAA


def test_unsupported_function_returns_an_exact_size_exception(honeypot):
    port, _ = honeypot
    # FC 0x63 is not implemented; expect an ILLEGAL FUNCTION exception.
    request = bytes.fromhex("00010000000601") + bytes([0x63])

    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(request + b"\x00\x00\x00\x01")
        response = _read_response(sock)

    assert len(response) == MBAP_HEADER_LEN + 2, "exception response must not echo request bytes"
    assert response[MBAP_HEADER_LEN] == 0x63 | 0x80
    assert response[MBAP_HEADER_LEN + 1] == 0x01


def test_a_malformed_frame_is_logged_and_the_service_survives(honeypot):
    port, log_path = honeypot

    # Protocol identifier 0xDEAD is not Modbus.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(bytes.fromhex("0001dead000601") + b"\x03\x00\x00\x00\x01")
        assert sock.recv(256) == b"", "malformed frame must not be answered"

    malformed = _wait_for_event(log_path, "modbus_malformed")
    assert malformed["details"]["reason"] == "bad_protocol_id"

    # The service is still healthy afterwards.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(build_read_holding_registers_request(9, 1, 0, 1))
        assert parse_mbap(_read_response(sock)).transaction_id == 9


def test_connection_events_are_emitted(honeypot):
    port, log_path = honeypot

    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(build_read_holding_registers_request(1, 1, 0, 1))
        _read_response(sock)

    assert _wait_for_event(log_path, "connection")["details"]["client_ip"] == "127.0.0.1"
    assert _wait_for_event(log_path, "modbus_request")["details"]["function_code"] == 3
    assert _wait_for_event(log_path, "modbus_response")["details"]["bytes_out"] == 11
    _wait_for_event(log_path, "connection_closed")
