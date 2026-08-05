"""Tests for the standard-library Modbus/TCP deception server."""

from __future__ import annotations

import json
import socket
import threading

import pytest

from ics_deception.common.events import EventPublisher
from ics_deception.common.modbus import (
    EXC_ILLEGAL_DATA_ADDRESS,
    EXC_ILLEGAL_DATA_VALUE,
    EXC_ILLEGAL_FUNCTION,
    FC_READ_HOLDING_REGISTERS,
    FC_WRITE_SINGLE_REGISTER,
    MBAP_HEADER_LEN,
    build_read_holding_registers_request,
    build_response,
    build_write_single_register_request,
    parse_mbap,
)
from ics_deception.honeypots.modbus_server import ModbusDeceptionServer, RegisterBank


@pytest.fixture
def server(event_log):
    """A running loopback Modbus server on a kernel-assigned free port."""
    bank = RegisterBank(size=256, critical_start=100, critical_end=110)
    publisher = EventPublisher(source="modbus_server", echo=False)
    instance = ModbusDeceptionServer(
        host="127.0.0.1", port=0, bank=bank, publisher=publisher, client_timeout=5.0
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def exchange(server: ModbusDeceptionServer, request: bytes, chunks: int = 1) -> bytes:
    """Send a request (optionally split across writes) and read one response."""
    with socket.create_connection((server.host, server.port), timeout=5) as sock:
        sock.settimeout(5)
        if chunks <= 1:
            sock.sendall(request)
        else:
            step = max(1, len(request) // chunks)
            for offset in range(0, len(request), step):
                sock.sendall(request[offset : offset + step])
        header = _recv_exact(sock, MBAP_HEADER_LEN)
        parsed = parse_mbap(header)
        assert parsed is not None
        return header + _recv_exact(sock, parsed.pdu_len)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        assert chunk, "connection closed before the full response arrived"
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# -- FC03 reads -------------------------------------------------------------


def test_fc03_reads_holding_registers(server):
    server.bank.write(0, 0x1234)
    server.bank.write(1, 0xBEEF)

    response = exchange(server, build_read_holding_registers_request(7, 1, 0, 2))

    header = parse_mbap(response)
    assert header.transaction_id == 7
    assert header.protocol_id == 0
    assert header.unit_id == 1
    pdu = response[MBAP_HEADER_LEN:]
    assert pdu[0] == FC_READ_HOLDING_REGISTERS
    assert pdu[1] == 4  # byte count
    assert int.from_bytes(pdu[2:4], "big") == 0x1234
    assert int.from_bytes(pdu[4:6], "big") == 0xBEEF


def test_fc03_mbap_length_matches_the_payload(server):
    response = exchange(server, build_read_holding_registers_request(1, 1, 0, 5))

    header = parse_mbap(response)
    assert header.length == len(response) - (MBAP_HEADER_LEN - 1)
    assert len(response) == header.total_frame_len


def test_fc03_rejects_an_out_of_range_address(server):
    response = exchange(server, build_read_holding_registers_request(1, 1, 250, 20))

    pdu = response[MBAP_HEADER_LEN:]
    assert pdu[0] == FC_READ_HOLDING_REGISTERS | 0x80
    assert pdu[1] == EXC_ILLEGAL_DATA_ADDRESS


@pytest.mark.parametrize("quantity", [0, 126, 2000])
def test_fc03_rejects_an_invalid_quantity(server, quantity):
    response = exchange(server, build_read_holding_registers_request(1, 1, 0, quantity))

    pdu = response[MBAP_HEADER_LEN:]
    assert pdu[0] == FC_READ_HOLDING_REGISTERS | 0x80
    assert pdu[1] == EXC_ILLEGAL_DATA_VALUE


# -- FC06 writes ------------------------------------------------------------


def test_fc06_writes_a_register_and_echoes_the_request(server):
    request = build_write_single_register_request(42, 1, 5, 0xCAFE)

    response = exchange(server, request)

    assert response == request  # a successful FC06 echoes address and value
    assert server.bank.read(5, 1) == [0xCAFE]


def test_fc06_value_is_readable_back_with_fc03(server):
    exchange(server, build_write_single_register_request(1, 1, 20, 0x0BAD))

    response = exchange(server, build_read_holding_registers_request(2, 1, 20, 1))

    pdu = response[MBAP_HEADER_LEN:]
    assert int.from_bytes(pdu[2:4], "big") == 0x0BAD


def test_fc06_rejects_an_out_of_range_address(server):
    response = exchange(server, build_write_single_register_request(1, 1, 9999, 1))

    pdu = response[MBAP_HEADER_LEN:]
    assert pdu[0] == FC_WRITE_SINGLE_REGISTER | 0x80
    assert pdu[1] == EXC_ILLEGAL_DATA_ADDRESS


def test_fc06_write_to_a_critical_register_raises_a_sabotage_event(server, event_log):
    exchange(server, build_write_single_register_request(1, 1, 105, 0xDEAD))

    records = [
        json.loads(line)
        for line in event_log.read_text(encoding="utf-8").strip().splitlines()
        if line.strip()
    ]
    alerts = [r for r in records if r["event_type"] == "sabotage_detected"]
    assert len(alerts) == 1
    assert alerts[0]["details"]["address"] == 105
    assert alerts[0]["details"]["alert"] == "write_to_critical_register"


def test_fc06_write_outside_the_critical_range_raises_no_alert(server, event_log):
    exchange(server, build_write_single_register_request(1, 1, 5, 0xDEAD))

    records = [
        json.loads(line)
        for line in event_log.read_text(encoding="utf-8").strip().splitlines()
        if line.strip()
    ]
    assert not [r for r in records if r["event_type"] == "sabotage_detected"]


# -- unsupported functions and malformed input ------------------------------


@pytest.mark.parametrize("function_code", [0x02, 0x04, 0x08, 0x0F, 0x11, 0x2B, 0x7F])
def test_unsupported_function_codes_return_an_illegal_function_exception(server, function_code):
    request = build_response(9, 1, bytes([function_code, 0, 0, 0, 1]))

    response = exchange(server, request)

    pdu = response[MBAP_HEADER_LEN:]
    assert pdu[0] == function_code | 0x80
    assert pdu[1] == EXC_ILLEGAL_FUNCTION
    # An exception response is exactly MBAP + 2 bytes; no request bytes echoed.
    assert len(response) == MBAP_HEADER_LEN + 2


def test_exception_response_preserves_the_transaction_id(server):
    request = build_response(0xABCD, 3, bytes([0x63, 0, 0, 0, 1]))

    response = exchange(server, request)

    header = parse_mbap(response)
    assert header.transaction_id == 0xABCD
    assert header.unit_id == 3


def test_fc03_with_a_truncated_pdu_returns_an_exception(server):
    # Declared length is honest, but the PDU is one byte short for FC03.
    request = build_response(1, 1, bytes([FC_READ_HOLDING_REGISTERS, 0, 0, 0]))

    response = exchange(server, request)

    pdu = response[MBAP_HEADER_LEN:]
    assert pdu[0] == FC_READ_HOLDING_REGISTERS | 0x80
    assert pdu[1] == EXC_ILLEGAL_DATA_VALUE


# -- stream framing ---------------------------------------------------------


def test_a_request_split_across_writes_is_reassembled(server):
    server.bank.write(0, 0x4321)

    response = exchange(server, build_read_holding_registers_request(3, 1, 0, 1), chunks=6)

    pdu = response[MBAP_HEADER_LEN:]
    assert int.from_bytes(pdu[2:4], "big") == 0x4321


def test_two_requests_in_one_write_are_both_serviced(server):
    server.bank.write(0, 0x1111)
    server.bank.write(1, 0x2222)
    pipelined = build_read_holding_registers_request(1, 1, 0, 1) + (
        build_read_holding_registers_request(2, 1, 1, 1)
    )

    with socket.create_connection((server.host, server.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(pipelined)
        first = _recv_exact(sock, MBAP_HEADER_LEN)
        first += _recv_exact(sock, parse_mbap(first).pdu_len)
        second = _recv_exact(sock, MBAP_HEADER_LEN)
        second += _recv_exact(sock, parse_mbap(second).pdu_len)

    assert parse_mbap(first).transaction_id == 1
    assert int.from_bytes(first[MBAP_HEADER_LEN + 2 : MBAP_HEADER_LEN + 4], "big") == 0x1111
    assert parse_mbap(second).transaction_id == 2
    assert int.from_bytes(second[MBAP_HEADER_LEN + 2 : MBAP_HEADER_LEN + 4], "big") == 0x2222


def test_a_bad_protocol_id_is_logged_and_the_connection_is_dropped(server, event_log):
    frame = bytearray(build_read_holding_registers_request(1, 1, 0, 1))
    frame[2:4] = (0x1234).to_bytes(2, "big")  # not Modbus

    with socket.create_connection((server.host, server.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(bytes(frame))
        assert sock.recv(256) == b""  # dropped without a reply

    records = [
        json.loads(line)
        for line in event_log.read_text(encoding="utf-8").strip().splitlines()
        if line.strip()
    ]
    malformed = [r for r in records if r["event_type"] == "modbus_malformed"]
    assert malformed and malformed[0]["details"]["reason"] == "bad_protocol_id"


def test_an_impossible_mbap_length_is_rejected(server, event_log):
    frame = bytearray(build_read_holding_registers_request(1, 1, 0, 1))
    frame[4:6] = (0xFFFF).to_bytes(2, "big")

    with socket.create_connection((server.host, server.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(bytes(frame))
        assert sock.recv(256) == b""

    records = [
        json.loads(line)
        for line in event_log.read_text(encoding="utf-8").strip().splitlines()
        if line.strip()
    ]
    malformed = [r for r in records if r["event_type"] == "modbus_malformed"]
    assert malformed and malformed[0]["details"]["reason"] == "bad_mbap_length"


def test_the_server_survives_a_burst_of_malformed_frames(server):
    for payload in (b"\x00", b"garbage", b"\xff" * 64, b""):
        with socket.create_connection((server.host, server.port), timeout=5) as sock:
            sock.settimeout(5)
            if payload:
                sock.sendall(payload)

    # Still serving afterwards.
    response = exchange(server, build_read_holding_registers_request(1, 1, 0, 1))
    assert parse_mbap(response).transaction_id == 1
