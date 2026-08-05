"""Tests for the fake PLC node.

Covers the two defects the original prototype had: it sent a non-Modbus
``HEARTBEAT`` string, and it wrote its state file non-atomically.
"""

from __future__ import annotations

import json
import threading

import pytest

from ics_deception.common.events import EventPublisher
from ics_deception.honeypots.modbus_server import ModbusDeceptionServer, RegisterBank
from ics_deception.iot_nodes.fake_plc import main as fake_plc_main
from ics_deception.iot_nodes.fake_plc import poll_once, write_state_atomically


@pytest.fixture
def server(event_log):
    bank = RegisterBank(size=256)
    instance = ModbusDeceptionServer(
        host="127.0.0.1",
        port=0,
        bank=bank,
        publisher=EventPublisher(source="modbus_server", echo=False),
        client_timeout=5.0,
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def test_poll_once_speaks_valid_modbus_to_the_server(server):
    server.bank.write(0, 0x0101)
    server.bank.write(1, 0x0202)

    result = poll_once(server.host, server.port, unit_id=1, address=0, quantity=2)

    assert result["ok"] is True
    assert result["registers"] == [0x0101, 0x0202]


def test_poll_once_reports_a_modbus_exception_without_raising(server):
    # Quantity 0 is illegal, so the server answers with an exception PDU.
    result = poll_once(server.host, server.port, address=0, quantity=0)

    assert result["ok"] is False
    assert result["exception_code"] == 0x03
    assert result["registers"] == []


def test_poll_once_raises_when_the_target_is_absent(server):
    server.shutdown()
    server.server_close()

    with pytest.raises(OSError):
        poll_once(server.host, server.port, timeout=1.0)


def test_the_server_records_a_well_formed_request_not_a_malformed_frame(server, event_log):
    poll_once(server.host, server.port, address=0, quantity=4)

    records = [
        json.loads(line)
        for line in event_log.read_text(encoding="utf-8").strip().splitlines()
        if line.strip()
    ]
    assert [r for r in records if r["event_type"] == "modbus_request"]
    assert not [r for r in records if r["event_type"] == "modbus_malformed"]


def test_write_state_atomically_leaves_no_temporary_files(tmp_path):
    target = tmp_path / "plc_state.json"

    write_state_atomically({"ok": True, "registers": [1, 2]}, target)

    assert json.loads(target.read_text(encoding="utf-8"))["registers"] == [1, 2]
    assert [p.name for p in tmp_path.iterdir()] == ["plc_state.json"]


def test_write_state_atomically_replaces_previous_content(tmp_path):
    target = tmp_path / "plc_state.json"
    write_state_atomically({"generation": 1}, target)

    write_state_atomically({"generation": 2}, target)

    assert json.loads(target.read_text(encoding="utf-8")) == {"generation": 2}
    assert len(list(tmp_path.iterdir())) == 1


def test_cli_single_shot_writes_the_state_file(server, tmp_path, event_log):
    state_file = tmp_path / "state.json"

    exit_code = fake_plc_main(
        [
            "--target-host",
            server.host,
            "--target-port",
            str(server.port),
            "--quantity",
            "4",
            "--once",
            "--state-file",
            str(state_file),
        ]
    )

    assert exit_code == 0
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["ok"] is True
    assert len(state["registers"]) == 4
    assert state["error"] is None
    assert state["timestamp"]


def test_cli_records_a_failure_when_the_target_is_unreachable(tmp_path, event_log):
    state_file = tmp_path / "state.json"

    exit_code = fake_plc_main(
        [
            "--target-host",
            "127.0.0.1",
            "--target-port",
            "1",  # nothing listens here
            "--once",
            "--timeout",
            "1",
            "--state-file",
            str(state_file),
        ]
    )

    assert exit_code == 1
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["ok"] is False
    assert state["error"]
