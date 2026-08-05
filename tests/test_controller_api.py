"""Tests for the FastAPI controller."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ics_deception.common.events import EventPublisher
from ics_deception.common.paths import plc_state_path
from ics_deception.controller.app import create_app
from ics_deception.controller.config import (
    ComponentConfig,
    ConfigError,
    ControllerConfig,
    default_config,
    load_config,
    write_default_config,
)


@pytest.fixture
def client(runtime_dir, approved_pcap_dir, tmp_path):
    """A controller test client with isolated runtime and capture directories."""
    config = default_config()
    config.pcap_dir = str(approved_pcap_dir)
    publisher = EventPublisher(source="controller", echo=False)
    app = create_app(config=config, publisher=publisher, root=tmp_path)
    with TestClient(app) as test_client:
        yield test_client


# -- health and status ------------------------------------------------------


def test_health_reports_ok_and_loopback_binding(client):
    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["host"] == "127.0.0.1"
    assert payload["replay_active"] is False
    assert "modbus_python" in payload["components"]


def test_status_lists_every_component_as_stopped(client):
    response = client.get("/status")

    assert response.status_code == 200
    components = response.json()["components"]
    assert set(components) == {"modbus_python", "modbus_native", "dnp3", "fake_plc"}
    for record in components.values():
        assert record["status"] == "stopped"
        assert record["pid"] is None


def test_nothing_starts_automatically(client):
    """Default config has every component disabled and non-autostart."""
    components = client.get("/status").json()["components"]

    assert all(record["status"] == "stopped" for record in components.values())
    assert all(record["enabled"] is False for record in components.values())


# -- logs -------------------------------------------------------------------


def test_logs_returns_parsed_objects_not_strings(client, event_log):
    EventPublisher(source="unit-test", echo=False).emit("probe", index=1)

    payload = client.get("/logs").json()

    assert payload["count"] >= 1
    assert all(isinstance(record, dict) for record in payload["logs"])
    probe = [r for r in payload["logs"] if r.get("event_type") == "probe"]
    assert probe and probe[0]["details"]["index"] == 1


def test_logs_are_empty_when_no_event_log_exists(client, event_log):
    # The controller's own startup event created the log; remove it so the
    # "no log file yet" branch is what gets exercised.
    event_log.unlink()

    payload = client.get("/logs").json()

    assert payload["logs"] == []
    assert payload["count"] == 0
    assert payload["event_log"] == str(event_log)


def test_logs_respects_the_limit(client, event_log):
    publisher = EventPublisher(source="unit-test", echo=False)
    for index in range(10):
        publisher.emit("probe", index=index)

    payload = client.get("/logs", params={"limit": 3}).json()

    assert payload["count"] == 3
    assert [r["details"]["index"] for r in payload["logs"]] == [7, 8, 9]


def test_a_corrupt_log_line_is_surfaced_not_dropped(client, event_log):
    EventPublisher(source="unit-test", echo=False).emit("good")
    with open(event_log, "a", encoding="utf-8") as handle:
        handle.write("{not valid json\n")

    payload = client.get("/logs").json()

    assert payload["logs"][-1]["_unparsed"].startswith("{not valid json")


def test_logs_rejects_an_out_of_range_limit(client):
    assert client.get("/logs", params={"limit": 0}).status_code == 422
    assert client.get("/logs", params={"limit": 99999}).status_code == 422


# -- ics-values -------------------------------------------------------------


def test_ics_values_returns_404_when_no_plc_state_exists(client):
    response = client.get("/ics-values")

    assert response.status_code == 404
    assert "no PLC state" in response.json()["detail"]


def test_ics_values_returns_the_plc_state(client, runtime_dir):
    state = {"ok": True, "registers": [1, 2, 3], "target": "127.0.0.1:5020"}
    plc_state_path().write_text(json.dumps(state), encoding="utf-8")

    response = client.get("/ics-values")

    assert response.status_code == 200
    assert response.json() == state


def test_ics_values_reports_503_for_unreadable_state(client, runtime_dir):
    plc_state_path().write_text("{ truncated", encoding="utf-8")

    assert client.get("/ics-values").status_code == 503


# -- component control ------------------------------------------------------


def test_starting_an_unknown_component_returns_404(client):
    assert client.post("/components/nope/start").status_code == 404
    assert client.post("/components/nope/stop").status_code == 404


def test_starting_a_disabled_component_returns_409(client):
    response = client.post("/components/dnp3/start")

    assert response.status_code == 409
    assert "disabled" in response.json()["detail"]


def test_stopping_a_stopped_component_succeeds(client):
    response = client.post("/components/dnp3/stop")

    assert response.status_code == 200
    assert response.json()["stopped"] == "dnp3"


def test_an_enabled_component_starts_logs_and_stops(runtime_dir, approved_pcap_dir, tmp_path):
    """Full child-process lifecycle: spawn, redirect output, report, terminate."""
    config = default_config()
    config.components["probe"] = ComponentConfig(
        kind="python",
        # Writes one line, then idles so the process is observably running.
        args=["-c", "print('probe-alive', flush=True)\nimport time; time.sleep(60)"],
        enabled=True,
        autostart=False,
    )
    app = create_app(
        config=config,
        publisher=EventPublisher(source="controller", echo=False),
        root=tmp_path,
    )

    with TestClient(app) as test_client:
        started = test_client.post("/components/probe/start")
        assert started.status_code == 200
        info = started.json()["status"]
        assert info["status"] == "running"
        assert info["pid"] is not None

        # stdout goes to a per-component log file, never to an unread PIPE.
        log_file = Path(info["log_file"])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if log_file.is_file() and "probe-alive" in log_file.read_text(encoding="utf-8"):
                break
            time.sleep(0.1)
        assert log_file.is_file(), "component log file was not created"
        assert "probe-alive" in log_file.read_text(encoding="utf-8")

        assert test_client.get("/status").json()["components"]["probe"]["status"] == "running"

        stopped = test_client.post("/components/probe/stop")
        assert stopped.status_code == 200
        assert stopped.json()["status"]["status"] == "stopped"
        assert stopped.json()["status"]["pid"] is None


def test_a_binary_component_with_a_missing_executable_fails_without_crashing(
    runtime_dir, approved_pcap_dir, tmp_path
):
    """A broken component reports its error; the controller stays up."""
    config = default_config()
    config.components["broken"] = ComponentConfig(
        kind="binary", command=["build/does-not-exist"], enabled=True
    )
    app = create_app(
        config=config,
        publisher=EventPublisher(source="controller", echo=False),
        root=tmp_path,
    )

    with TestClient(app) as test_client:
        response = test_client.post("/components/broken/start")
        assert response.status_code == 500
        assert "not found" in response.json()["detail"]

        # The controller is still serving, and reports the failure.
        status = test_client.get("/status").json()["components"]["broken"]
        assert status["status"] == "failed"
        assert "not found" in status["last_error"]
        assert test_client.get("/health").json()["status"] == "ok"


# -- replay -----------------------------------------------------------------


def test_replay_rejects_an_unsupported_extension(client):
    response = client.post("/replay", json={"pcap_path": "notes.txt"})

    assert response.status_code == 400


def test_replay_rejects_path_traversal(client):
    response = client.post("/replay", json={"pcap_path": "../../etc/passwd.pcap"})

    assert response.status_code == 403


def test_replay_rejects_an_absolute_path_outside_the_approved_directory(client, tmp_path):
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1")

    response = client.post("/replay", json={"pcap_path": str(outside)})

    assert response.status_code == 403


def test_replay_rejects_a_missing_capture(client):
    response = client.post("/replay", json={"pcap_path": "absent.pcap"})

    assert response.status_code == 404


def test_replay_rejects_unknown_body_fields(client):
    response = client.post("/replay", json={"pcap_path": "sample.pcap", "shell": "rm -rf /"})

    assert response.status_code == 422


# -- configuration ----------------------------------------------------------


def test_pcap_dir_defaults_to_the_environment_when_unset(runtime_dir, approved_pcap_dir, tmp_path):
    """With no `pcap_dir` in the config, ICS_DECEPTION_PCAP_DIR is used."""
    config = default_config()
    assert config.pcap_dir is None

    app = create_app(
        config=config,
        publisher=EventPublisher(source="controller", echo=False),
        root=tmp_path,
    )
    with TestClient(app) as test_client:
        payload = test_client.get("/health").json()

    assert payload["approved_pcap_dir"] == str(approved_pcap_dir)


def test_default_config_disables_everything():
    config = default_config()

    assert config.host == "127.0.0.1"
    assert config.components
    assert all(not c.enabled for c in config.components.values())
    assert all(not c.autostart for c in config.components.values())


def test_load_config_falls_back_to_defaults_for_a_missing_file(tmp_path):
    config = load_config(tmp_path / "absent.json")

    assert config.host == "127.0.0.1"


def test_load_config_rejects_malformed_json(tmp_path):
    path = tmp_path / "controller.json"
    path.write_text("{ not json", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_rejects_an_unknown_component_kind(tmp_path):
    path = tmp_path / "controller.json"
    path.write_text(
        json.dumps({"components": {"x": {"kind": "shell", "command": ["sh"]}}}), encoding="utf-8"
    )

    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_rejects_a_python_component_without_args(tmp_path):
    path = tmp_path / "controller.json"
    path.write_text(json.dumps({"components": {"x": {"kind": "python"}}}), encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(path)


def test_round_trip_of_the_written_default_config(tmp_path):
    path = write_default_config(tmp_path / "controller.json")

    assert load_config(path).model_dump() == default_config().model_dump()


def test_a_relative_executable_may_not_escape_the_project_root(tmp_path):
    component = ComponentConfig(kind="binary", command=["../../../bin/sh"], enabled=True)

    with pytest.raises(ValueError, match="escapes the project root"):
        component.resolve_executable(tmp_path)


def test_a_missing_relative_executable_is_rejected(tmp_path):
    component = ComponentConfig(kind="binary", command=["build/absent"], enabled=True)

    with pytest.raises(ValueError, match="not found"):
        component.resolve_executable(tmp_path)


def test_controller_config_rejects_unknown_top_level_fields():
    with pytest.raises(ValidationError):
        ControllerConfig.model_validate({"host": "127.0.0.1", "unexpected": True})
