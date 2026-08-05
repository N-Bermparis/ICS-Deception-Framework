"""Evidence integration with the real, running services.

The point of these tests is the thing that was previously untested: setting the
**documented environment variables** must make actual service events appear in
the signed evidence log. Before the shared publisher factory existed, nothing
called ``sink_from_env()``, so the documented configuration did nothing at all
in a real deployment while dependency-injected tests passed happily.
"""

from __future__ import annotations

import json
import socket
import threading

import pytest

from ics_deception.common.events import Event, EventPublisher
from ics_deception.common.publisher import (
    create_event_publisher,
    evidence_status,
    reset_shared_sink,
)
from ics_deception.pqc_evidence import EvidenceMode
from ics_deception.pqc_evidence.collector import EvidenceCollector
from ics_deception.pqc_evidence.integration import (
    ENV_EVIDENCE_LOG,
    ENV_EVIDENCE_MODE,
    ENV_KEY_ID,
    ENV_NODE_ID,
    ENV_PRIVATE_KEY,
    ENV_STATE,
    EvidenceSink,
    EvidenceSinkConfig,
    sink_from_env,
)
from ics_deception.pqc_evidence.signer import SignerError
from tests.pqc_evidence.conftest import KEY_ID, NODE_ID

pytestmark = pytest.mark.pqc


@pytest.fixture(autouse=True)
def clean_sink():
    """Every test starts and ends with no cached process-wide sink."""
    reset_shared_sink()
    yield
    reset_shared_sink()


@pytest.fixture
def key_file(tmp_path, signing_keypair):
    path = tmp_path / "node.key"
    path.write_bytes(signing_keypair.private_bytes)
    path.chmod(0o600)
    return path


@pytest.fixture
def configure_env(monkeypatch, tmp_path, key_file):
    """Set the documented environment variables, exactly as an operator would."""

    def apply(mode: str) -> dict[str, str]:
        settings = {
            ENV_EVIDENCE_MODE: mode,
            ENV_NODE_ID: NODE_ID,
            ENV_KEY_ID: KEY_ID,
            ENV_PRIVATE_KEY: str(key_file),
            ENV_EVIDENCE_LOG: str(tmp_path / "evidence.jsonl"),
            ENV_STATE: str(tmp_path / "state.json"),
        }
        for name, value in settings.items():
            monkeypatch.setenv(name, value)
        reset_shared_sink()
        return settings

    return apply


def make_sink(tmp_path, key_file, mode: str) -> EvidenceSink:
    return EvidenceSink(
        EvidenceSinkConfig(
            mode=mode,
            node_id=NODE_ID,
            key_id=KEY_ID,
            private_key_path=str(key_file),
            evidence_log=str(tmp_path / "evidence.jsonl"),
            state_path=str(tmp_path / "state.json"),
        )
    )


def evidence_lines(tmp_path) -> list[str]:
    path = tmp_path / "evidence.jsonl"
    if not path.is_file():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ===========================================================================
# The documented environment actually turns signing on
# ===========================================================================


def test_the_documented_environment_enables_live_signing(
    configure_env, tmp_path, registry, event_log
):
    configure_env("sign")

    publisher = create_event_publisher(source="modbus_honeypot", echo=False)
    publisher.emit("critical_register_write", client_ip="192.168.1.50", register=40001)

    lines = evidence_lines(tmp_path)
    assert lines, "setting the documented variables did not produce signed evidence"
    report = EvidenceCollector(registry).verify_stream(lines)
    assert report.valid is True, report.alert_counts
    assert json.loads(lines[0])["event"]["event_type"] == "critical_register_write"


def test_disabled_mode_preserves_unsigned_logging(monkeypatch, tmp_path, event_log):
    monkeypatch.setenv(ENV_EVIDENCE_MODE, "disabled")
    reset_shared_sink()

    publisher = create_event_publisher(source="modbus_honeypot", echo=False)
    publisher.emit("modbus_request", function_code=3)

    record = json.loads(event_log.read_text(encoding="utf-8").strip())
    assert record["event_type"] == "modbus_request"
    assert "signature" not in record
    assert publisher.evidence is None
    assert not (tmp_path / "evidence.jsonl").exists()


def test_no_configuration_at_all_preserves_unsigned_logging(monkeypatch, event_log):
    monkeypatch.delenv(ENV_EVIDENCE_MODE, raising=False)
    reset_shared_sink()

    publisher = create_event_publisher(source="dnp3_sensor", echo=False)
    publisher.emit("dnp3_interaction", length=16)

    assert json.loads(event_log.read_text(encoding="utf-8").strip())["source"] == "dnp3_sensor"
    assert publisher.evidence is None


def test_dual_mode_writes_both_raw_and_signed(configure_env, tmp_path, registry, event_log):
    configure_env("dual")

    publisher = create_event_publisher(source="dnp3_sensor", echo=False)
    publisher.emit("dnp3_interaction", client_ip="10.0.0.5", length=16)

    raw = event_log.read_text(encoding="utf-8").strip()
    assert json.loads(raw)["event_type"] == "dnp3_interaction"
    lines = evidence_lines(tmp_path)
    assert lines
    assert EvidenceCollector(registry).verify_stream(lines).valid is True


def test_sign_mode_writes_only_signed_evidence(configure_env, tmp_path, registry, event_log):
    configure_env("sign")

    create_event_publisher(source="modbus_honeypot", echo=False).emit("probe", x=1)

    assert not event_log.exists() or event_log.read_text(encoding="utf-8").strip() == ""
    assert evidence_lines(tmp_path)


def test_verify_only_mode_signs_nothing(monkeypatch, tmp_path, event_log):
    monkeypatch.setenv(ENV_EVIDENCE_MODE, "verify-only")
    monkeypatch.setenv(ENV_EVIDENCE_LOG, str(tmp_path / "evidence.jsonl"))
    monkeypatch.setenv(ENV_STATE, str(tmp_path / "state.json"))
    reset_shared_sink()

    publisher = create_event_publisher(source="controller", echo=False)
    publisher.emit("controller_startup")

    assert event_log.read_text(encoding="utf-8").strip()
    assert not (tmp_path / "evidence.jsonl").exists()


def test_enabling_without_a_key_fails_loudly(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_EVIDENCE_MODE, "sign")
    monkeypatch.setenv(ENV_NODE_ID, NODE_ID)
    monkeypatch.setenv(ENV_KEY_ID, KEY_ID)
    monkeypatch.delenv(ENV_PRIVATE_KEY, raising=False)
    reset_shared_sink()

    with pytest.raises(SignerError, match="cannot start"):
        create_event_publisher(source="modbus_honeypot")


def test_enabling_with_a_missing_key_file_fails_loudly(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_EVIDENCE_MODE, "sign")
    monkeypatch.setenv(ENV_NODE_ID, NODE_ID)
    monkeypatch.setenv(ENV_KEY_ID, KEY_ID)
    monkeypatch.setenv(ENV_PRIVATE_KEY, str(tmp_path / "absent.key"))
    reset_shared_sink()

    with pytest.raises(SignerError):
        create_event_publisher(source="modbus_honeypot")


def test_an_unknown_mode_is_rejected(monkeypatch):
    monkeypatch.setenv(ENV_EVIDENCE_MODE, "please-sign-everything")
    reset_shared_sink()

    with pytest.raises(SignerError):
        create_event_publisher(source="modbus_honeypot")


def test_one_sink_is_shared_across_publishers(configure_env, tmp_path, registry):
    """All of a process's events belong to one chain in one file."""
    configure_env("sign")

    for source in ("modbus_server", "dnp3_sensor", "controller"):
        create_event_publisher(source=source, echo=False).emit("t")

    lines = evidence_lines(tmp_path)
    assert len(lines) == 3
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2, 3]
    assert EvidenceCollector(registry).verify_stream(lines).valid is True


def test_evidence_status_exposes_no_key_material(configure_env, tmp_path, key_file):
    configure_env("sign")
    create_event_publisher(source="modbus_server", echo=False).emit("t")

    status = evidence_status()
    rendered = json.dumps(status)

    assert status["enabled"] is True
    assert status["mode"] == EvidenceMode.SIGN
    assert status["metrics"]["signed"] == 1
    assert status["chain"]["last_sequence"] == 1
    secret = key_file.read_bytes()
    assert secret.hex()[:32] not in rendered
    assert "-----BEGIN" not in rendered


def test_status_is_disabled_without_configuration(monkeypatch):
    monkeypatch.delenv(ENV_EVIDENCE_MODE, raising=False)
    reset_shared_sink()

    assert evidence_status() == {"mode": "disabled", "enabled": False}


# ===========================================================================
# Live services
# ===========================================================================


def test_a_live_modbus_server_signs_its_events(configure_env, tmp_path, registry):
    """End to end through a real socket, with the service creating its own publisher."""
    from ics_deception.common.modbus import build_write_single_register_request
    from ics_deception.honeypots.modbus_server import ModbusDeceptionServer, RegisterBank

    configure_env("sign")
    server = ModbusDeceptionServer(
        host="127.0.0.1",
        port=0,
        bank=RegisterBank(size=256, critical_start=100, critical_end=110),
        client_timeout=5.0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection((server.host, server.port), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(build_write_single_register_request(1, 1, 105, 0xDEAD))
            sock.recv(256)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()

    lines = evidence_lines(tmp_path)
    report = EvidenceCollector(registry).verify_stream(lines)

    assert report.valid is True, report.alert_counts
    event_types = {json.loads(line)["event"]["event_type"] for line in lines}
    assert "sabotage_detected" in event_types


def test_a_live_dnp3_sensor_signs_its_events(configure_env, tmp_path, registry):
    from ics_deception.honeypots.dnp3_sensor import Dnp3InteractionSensor

    configure_env("sign")
    sensor = Dnp3InteractionSensor(host="127.0.0.1", port=0, client_timeout=2.0)
    thread = threading.Thread(target=sensor.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection((sensor.host, sensor.port), timeout=5) as sock:
            sock.settimeout(5)
            sock.recv(64)
            sock.sendall(b"\x05\x64probe")
            sock.recv(64)
    finally:
        sensor.shutdown()
        sensor.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()

    lines = evidence_lines(tmp_path)
    report = EvidenceCollector(registry).verify_stream(lines)

    assert report.valid is True, report.alert_counts
    assert any(json.loads(line)["event"]["event_type"] == "dnp3_interaction" for line in lines)


def test_the_fake_plc_signs_its_events(configure_env, tmp_path, registry):
    from ics_deception.honeypots.modbus_server import ModbusDeceptionServer, RegisterBank
    from ics_deception.iot_nodes.fake_plc import main as fake_plc_main

    configure_env("sign")
    # The Modbus server keeps its own unsigned publisher so only the PLC's
    # events reach the evidence log, making the assertion unambiguous.
    server = ModbusDeceptionServer(
        host="127.0.0.1",
        port=0,
        bank=RegisterBank(size=256),
        publisher=EventPublisher(source="modbus_server", echo=False),
        client_timeout=5.0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        exit_code = fake_plc_main(
            [
                "--target-host",
                server.host,
                "--target-port",
                str(server.port),
                "--once",
                "--state-file",
                str(tmp_path / "plc_state.json"),
            ]
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert exit_code == 0
    lines = evidence_lines(tmp_path)
    assert lines
    assert EvidenceCollector(registry).verify_stream(lines).valid is True
    assert any(json.loads(line)["event"]["source"] == "fake_plc" for line in lines)


def test_controller_lifecycle_events_are_signed(configure_env, tmp_path, registry):
    from fastapi.testclient import TestClient

    from ics_deception.controller.app import create_app
    from ics_deception.controller.config import default_config

    configure_env("sign")
    app = create_app(config=default_config(), root=tmp_path)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200

    lines = evidence_lines(tmp_path)
    report = EvidenceCollector(registry).verify_stream(lines)

    assert report.valid is True, report.alert_counts
    types = {json.loads(line)["event"]["event_type"] for line in lines}
    assert "controller_startup" in types
    assert "controller_shutdown" in types


def test_component_failure_events_are_signed(configure_env, tmp_path, registry):
    from fastapi.testclient import TestClient

    from ics_deception.controller.app import create_app
    from ics_deception.controller.config import ComponentConfig, default_config

    configure_env("sign")
    config = default_config()
    config.components["broken"] = ComponentConfig(
        kind="binary", command=["build/does-not-exist"], enabled=True
    )
    app = create_app(config=config, root=tmp_path)
    with TestClient(app) as client:
        assert client.post("/components/broken/start").status_code == 500

    lines = evidence_lines(tmp_path)
    types = {json.loads(line)["event"]["event_type"] for line in lines}

    assert "component_start_failed" in types
    assert EvidenceCollector(registry).verify_stream(lines).valid is True


COMPONENT_EVENTS = [
    ("modbus_honeypot", "critical_register_write", {"client_ip": "192.168.1.50"}),
    ("modbus_server", "modbus_request", {"function_code": 3}),
    ("dnp3_sensor", "dnp3_interaction", {"length": 16}),
    ("fake_ssh_banner", "login_attempt", {"username": "admin", "password_length": 8}),
    ("fake_telnet", "telnet_command", {"command": "status"}),
    ("pcap_loader", "modbus_packet", {"src": "10.0.0.1:40000"}),
    ("controller", "component_started", {"name": "modbus_native"}),
    ("controller", "component_stopped", {"returncode": 0}),
]


@pytest.mark.parametrize(("source", "event_type", "details"), COMPONENT_EVENTS)
def test_every_component_signs_through_the_factory(
    configure_env, tmp_path, registry, source, event_type, details
):
    configure_env("sign")

    create_event_publisher(source=source, echo=False).emit(event_type, **details)

    line = evidence_lines(tmp_path)[0]
    assert EvidenceCollector(registry).verify_stream([line]).valid is True
    record = json.loads(line)
    assert record["event"]["source"] == source
    assert record["event"]["event_type"] == event_type


# ===========================================================================
# Metrics
# ===========================================================================


def test_counters_advance_only_on_real_success(tmp_path, key_file):
    sink = make_sink(tmp_path, key_file, EvidenceMode.SIGN)

    sink.handle(Event(source="s", event_type="t", details={"n": 1}))
    metrics = sink.metrics.snapshot()

    assert metrics["received"] == 1
    assert metrics["signed"] == 1
    assert metrics["persisted"] == 1
    assert metrics["signing_failures"] == 0
    assert metrics["persistence_failures"] == 0


def test_a_signing_failure_increments_the_signing_counter(tmp_path, key_file, monkeypatch):
    sink = make_sink(tmp_path, key_file, EvidenceMode.SIGN)

    def explode(*args, **kwargs):
        raise SignerError("backend exploded")

    monkeypatch.setattr(sink._signer, "sign_event", explode)

    with pytest.raises(SignerError):
        sink.handle(Event(source="s", event_type="t"))

    metrics = sink.metrics.snapshot()
    assert metrics["received"] == 1
    assert metrics["signing_failures"] == 1
    assert metrics["signed"] == 0, "a failed signature must not count as signed"
    assert metrics["persisted"] == 0


def test_a_persistence_failure_is_counted_separately(tmp_path, key_file, monkeypatch):
    from ics_deception.pqc_evidence.evidence_store import TransactionAborted

    sink = make_sink(tmp_path, key_file, EvidenceMode.SIGN)

    def explode(*args, **kwargs):
        raise TransactionAborted("no space left on device")

    monkeypatch.setattr(sink._signer, "sign_event", explode)

    with pytest.raises(TransactionAborted):
        sink.handle(Event(source="s", event_type="t"))

    metrics = sink.metrics.snapshot()
    assert metrics["persistence_failures"] == 1
    assert metrics["signed"] == 0
    assert metrics["persisted"] == 0


def test_a_malformed_event_is_rejected_before_signing(tmp_path, key_file):
    sink = make_sink(tmp_path, key_file, EvidenceMode.SIGN)

    class Unserialisable:
        source = "s"
        event_type = "t"
        timestamp = "2026-08-05T18:15:00.000000Z"

        @property
        def details(self):
            raise RuntimeError("details blew up")

    with pytest.raises(SignerError):
        sink.handle(Unserialisable())

    metrics = sink.metrics.snapshot()
    assert metrics["rejected_before_signing"] == 1
    assert metrics["signed"] == 0


def test_metrics_are_concurrency_safe(tmp_path, key_file):
    sink = make_sink(tmp_path, key_file, EvidenceMode.SIGN)

    def worker() -> None:
        for _ in range(4):
            sink.handle(Event(source="s", event_type="t"))

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=180)

    metrics = sink.metrics.snapshot()
    assert metrics["received"] == 12
    assert metrics["signed"] == 12
    assert metrics["persisted"] == 12


def test_a_signing_failure_never_loses_the_plain_event(tmp_path, event_log, capsys):
    class Exploding:
        def handle(self, event):
            raise RuntimeError("signer exploded")

    publisher = EventPublisher(source="modbus_honeypot", echo=False, evidence=Exploding())
    publisher.emit("modbus_request", function_code=3)

    assert json.loads(event_log.read_text(encoding="utf-8").strip())["event_type"] == (
        "modbus_request"
    )
    assert "evidence signing failed" in capsys.readouterr().err


def test_sink_from_env_returns_none_when_disabled(monkeypatch):
    monkeypatch.setenv(ENV_EVIDENCE_MODE, "disabled")

    assert sink_from_env() is None


def test_an_oversized_event_is_replaced_by_a_bounded_digest(tmp_path, key_file):
    sink = make_sink(tmp_path, key_file, EvidenceMode.SIGN)
    bulky = Event(
        source="pcap_loader",
        event_type="huge",
        details={f"field_{n}": "y" * 400 for n in range(200)},
    )

    bounded = sink.bound_event(bulky)

    assert bounded["payload_truncated"] is True
    assert len(bounded["payload_sha3_256"]) == 64
    assert bounded["payload_bytes"] > 16 * 1024


def test_a_long_string_stays_bounded_end_to_end(tmp_path, key_file, registry):
    sink = make_sink(tmp_path, key_file, EvidenceMode.SIGN)
    publisher = EventPublisher(source="pcap_loader", echo=False, evidence=sink)

    publisher.emit("huge", blob="x" * 200_000)

    line = evidence_lines(tmp_path)[0]
    assert len(line) < 16 * 1024
    assert json.loads(line)["event"]["blob"].endswith("...[truncated]")
    assert EvidenceCollector(registry).verify_stream([line]).valid is True
