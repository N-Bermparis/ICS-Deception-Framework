"""Smoke and negative tests for the DNP3 sensor and the native decoys.

The DNP3 sensor is exercised in-process. The Telnet and SSH-banner decoys are
compiled binaries, so those tests build or locate them and drive real sockets;
they skip cleanly when no C++ toolchain is present.

Every test asserts on *behaviour we promise*: bounded input, timeouts,
structured logging, credential redaction and clean shutdown with no stray
processes.
"""

from __future__ import annotations

import contextlib
import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from ics_deception.common.events import EventPublisher
from ics_deception.honeypots.dnp3_sensor import (
    LINK_START,
    MAX_SAMPLE_BYTES,
    Dnp3InteractionSensor,
)
from tests.conftest import free_tcp_port

STARTUP_TIMEOUT = 10.0


def read_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ===========================================================================
# DNP3-inspired interaction sensor
# ===========================================================================


@pytest.fixture
def dnp3_sensor(event_log):
    sensor = Dnp3InteractionSensor(
        host="127.0.0.1",
        port=0,
        publisher=EventPublisher(source="dnp3_sensor", echo=False),
        client_timeout=2.0,
    )
    thread = threading.Thread(target=sensor.serve_forever, daemon=True)
    thread.start()
    try:
        yield sensor
    finally:
        sensor.shutdown()
        sensor.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "the DNP3 sensor thread did not stop"


def test_dnp3_sensor_starts_on_loopback(dnp3_sensor):
    assert dnp3_sensor.host == "127.0.0.1"
    assert dnp3_sensor.port > 1023, "tests must not use privileged ports"


def test_dnp3_sensor_emits_a_link_layer_start_sequence(dnp3_sensor):
    with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
        sock.settimeout(5)
        banner = sock.recv(64)

    assert banner.startswith(LINK_START)


def test_dnp3_sensor_replies_to_a_probe(dnp3_sensor):
    with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.recv(64)
        sock.sendall(b"\x05\x64\x05\xc9\x01\x00\x00\x04")
        reply = sock.recv(64)

    assert reply.startswith(LINK_START)


def test_dnp3_sensor_logs_structured_interaction_events(dnp3_sensor, event_log):
    with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.recv(64)
        sock.sendall(b"\x05\x64probe")
        sock.recv(64)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        events = read_events(event_log)
        if any(e["event_type"] == "dnp3_interaction" for e in events):
            break
        time.sleep(0.05)

    interaction = next(e for e in read_events(event_log) if e["event_type"] == "dnp3_interaction")
    assert interaction["details"]["client_ip"] == "127.0.0.1"
    assert interaction["details"]["length"] == len(b"\x05\x64probe")
    assert "hex_sample" in interaction["details"]


def test_dnp3_sensor_bounds_the_logged_payload_sample(dnp3_sensor, event_log):
    with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.recv(64)
        sock.sendall(b"A" * 4096)
        sock.recv(64)

    deadline = time.monotonic() + 5
    interaction = None
    while time.monotonic() < deadline and interaction is None:
        for event in read_events(event_log):
            if event["event_type"] == "dnp3_interaction":
                interaction = event
                break
        time.sleep(0.05)

    assert interaction is not None
    assert len(interaction["details"]["hex_sample"]) <= MAX_SAMPLE_BYTES * 2
    assert interaction["details"]["truncated"] is True


def test_dnp3_sensor_times_out_a_silent_peer(dnp3_sensor, event_log):
    with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=10) as sock:
        sock.settimeout(10)
        sock.recv(64)
        # Say nothing; the 2 s server-side timeout must fire and close us out.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if any(e["event_type"] == "dnp3_timeout" for e in read_events(event_log)):
                break
            time.sleep(0.1)

    assert any(e["event_type"] == "dnp3_timeout" for e in read_events(event_log))


def test_dnp3_sensor_logs_connection_open_and_close(dnp3_sensor, event_log):
    with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.recv(64)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        types = {e["event_type"] for e in read_events(event_log)}
        if {"dnp3_connection", "dnp3_connection_closed"} <= types:
            break
        time.sleep(0.05)

    types = {e["event_type"] for e in read_events(event_log)}
    assert "dnp3_connection" in types
    assert "dnp3_connection_closed" in types


def test_dnp3_sensor_survives_garbage_and_abrupt_disconnects(dnp3_sensor):
    for payload in (b"", b"\x00", b"\xff" * 512, b"GET / HTTP/1.1\r\n\r\n"):
        with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
            sock.settimeout(5)
            if payload:
                sock.sendall(payload)

    # Still serving afterwards.
    with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
        sock.settimeout(5)
        assert sock.recv(64).startswith(LINK_START)


def test_dnp3_sensor_handles_several_clients_without_blocking(dnp3_sensor):
    results: list[bool] = []
    lock = threading.Lock()

    def probe() -> None:
        with socket.create_connection((dnp3_sensor.host, dnp3_sensor.port), timeout=5) as sock:
            sock.settimeout(5)
            ok = sock.recv(64).startswith(LINK_START)
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=probe) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert results == [True] * 5


def test_dnp3_sensor_cli_rejects_bad_arguments():
    from ics_deception.honeypots.dnp3_sensor import main

    for argv in (["--port", "0"], ["--port", "99999"], ["--timeout", "0"], ["--timeout", "-1"]):
        with pytest.raises(SystemExit) as excinfo:
            main(argv)
        assert excinfo.value.code == 2


# ===========================================================================
# Native Telnet and SSH-banner decoys
# ===========================================================================


@pytest.fixture
def native_dir(native_build: Path) -> Path:
    """Freshly compiled decoys, from the session build fixture in conftest.

    Never a prebuilt ``build/`` from the working tree: a stale binary there
    would make these tests silently exercise old C++ sources.
    """
    return native_build


class DecoyProcess:
    """A started decoy binary, cleaned up unconditionally."""

    def __init__(self, binary: Path, port: int, log_path: Path, extra: list[str] | None = None):
        self.port = port
        self.log_path = log_path
        self.stdout_path = log_path.with_suffix(".out")
        # Held open for the process lifetime; closed in stop().
        self._handle = open(self.stdout_path, "wb")  # noqa: SIM115
        self.process = subprocess.Popen(
            [
                str(binary),
                "--bind",
                "127.0.0.1",
                "--port",
                str(port),
                "--timeout",
                "2",
                "--max-clients",
                "4",
                "--log",
                str(log_path),
                *(extra or []),
            ],
            stdin=subprocess.DEVNULL,
            stdout=self._handle,
            stderr=subprocess.STDOUT,
        )

    def wait_until_listening(self) -> None:
        """Wait for the decoy's own startup announcement.

        Deliberately does *not* probe with a TCP connection: a probe would be
        recorded as a real session and pollute the very event log these tests
        assert on. The decoy prints and flushes a "listening on" line once its
        socket is bound, which is both accurate and side-effect free.
        """
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.stdout_path.read_text(encoding="utf-8", errors="replace")
                pytest.fail(f"decoy exited early ({self.process.returncode}):\n{output}")
            if self.stdout_path.is_file():
                text = self.stdout_path.read_text(encoding="utf-8", errors="replace")
                if f"listening on 127.0.0.1:{self.port}" in text:
                    return
            time.sleep(0.05)
        pytest.fail(f"decoy did not announce listening on {self.port} within {STARTUP_TIMEOUT}s")

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.process.kill()
                self.process.wait(timeout=5)
        self._handle.close()


@pytest.fixture
def telnet_decoy(native_dir, tmp_path):
    decoy = DecoyProcess(native_dir / "fake_telnet", free_tcp_port(), tmp_path / "telnet.jsonl")
    try:
        decoy.wait_until_listening()
        yield decoy
    finally:
        decoy.stop()
        assert decoy.process.poll() is not None, "the telnet decoy is still running"


@pytest.fixture
def ssh_decoy(native_dir, tmp_path):
    decoy = DecoyProcess(native_dir / "fake_ssh", free_tcp_port(), tmp_path / "ssh.jsonl")
    try:
        decoy.wait_until_listening()
        yield decoy
    finally:
        decoy.stop()
        assert decoy.process.poll() is not None, "the ssh decoy is still running"


def converse(port: int, script: list[bytes], read_timeout: float = 5.0) -> bytes:
    """Send each line and collect everything the decoy says back."""
    received = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=read_timeout) as sock:
        sock.settimeout(read_timeout)
        for line in script:
            time.sleep(0.15)
            with contextlib.suppress(TimeoutError, OSError):
                received.extend(sock.recv(4096))
            sock.sendall(line)
        time.sleep(0.3)
        with contextlib.suppress(TimeoutError, OSError):
            received.extend(sock.recv(4096))
    return bytes(received)


def drain_until_closed(sock: socket.socket, timeout: float = 8.0) -> bytes:
    """Read until the decoy closes the connection, or the timeout expires."""
    received = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)


def wait_for_event(log_path: Path, event_type: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in read_events(log_path):
            if event.get("event_type") == event_type:
                return event
        time.sleep(0.1)
    seen = sorted({e.get("event_type", "?") for e in read_events(log_path)})
    pytest.fail(f"no {event_type!r} event within {timeout}s; observed: {seen}")


# -- Telnet -----------------------------------------------------------------


def test_telnet_decoy_presents_a_login_prompt(telnet_decoy):
    with socket.create_connection(("127.0.0.1", telnet_decoy.port), timeout=5) as sock:
        sock.settimeout(5)
        banner = sock.recv(256)

    assert b"RTU-358" in banner
    assert b"Login:" in banner


def test_telnet_decoy_accepts_a_login_and_serves_commands(telnet_decoy):
    transcript = converse(
        telnet_decoy.port, [b"operator\r\n", b"hunter2\r\n", b"status\r\n", b"exit\r\n"]
    )

    assert b"Access granted" in transcript
    assert b"STATUS: PLC RUN" in transcript
    assert b"Goodbye" in transcript


def test_telnet_decoy_answers_unknown_commands(telnet_decoy):
    transcript = converse(
        telnet_decoy.port, [b"user\r\n", b"pass\r\n", b"rm -rf /\r\n", b"exit\r\n"]
    )

    assert b"Unknown command" in transcript


def test_telnet_decoy_logs_commands_structurally(telnet_decoy):
    converse(telnet_decoy.port, [b"user\r\n", b"pass\r\n", b"diag\r\n", b"exit\r\n"])

    event = wait_for_event(telnet_decoy.log_path, "telnet_command")
    assert event["source"] == "fake_telnet"
    assert event["details"]["command"] == "diag"
    assert event["details"]["client_ip"] == "127.0.0.1"


def test_telnet_decoy_redacts_the_password_by_default(telnet_decoy):
    converse(telnet_decoy.port, [b"operator\r\n", b"sup3rSecret!\r\n", b"exit\r\n"])

    event = wait_for_event(telnet_decoy.log_path, "login_attempt")
    details = event["details"]

    assert details["username"] == "operator"
    assert details["password_length"] == len("sup3rSecret!")
    assert details["password_shape"] == "aA0#"
    assert details["credentials_captured"] == 0
    assert "password" not in details
    assert "sup3rSecret!" not in telnet_decoy.log_path.read_text(encoding="utf-8")


def test_telnet_decoy_bounds_an_overlong_line(telnet_decoy):
    """An over-long line ends the session instead of buffering without limit."""
    with socket.create_connection(("127.0.0.1", telnet_decoy.port), timeout=10) as sock:
        sock.settimeout(10)
        sock.recv(256)
        sock.sendall(b"A" * 4096 + b"\r\n")
        # Stay connected and drain until the decoy hangs up, so the close
        # reason reflects its decision rather than our disconnect.
        drain_until_closed(sock)

    event = wait_for_event(telnet_decoy.log_path, "telnet_connection_closed")
    assert event["details"]["reason"] == "line_too_long"


def test_telnet_decoy_times_out_a_silent_peer(telnet_decoy):
    with socket.create_connection(("127.0.0.1", telnet_decoy.port), timeout=10) as sock:
        sock.settimeout(10)
        sock.recv(256)
        time.sleep(3.0)  # server timeout is 2 s

    event = wait_for_event(telnet_decoy.log_path, "telnet_connection_closed", timeout=8)
    assert event["details"]["reason"] in ("timeout", "login_incomplete")


def test_telnet_decoy_survives_binary_garbage(telnet_decoy):
    with socket.create_connection(("127.0.0.1", telnet_decoy.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(bytes(range(256)) * 4)
        time.sleep(0.3)

    # Still serving.
    with socket.create_connection(("127.0.0.1", telnet_decoy.port), timeout=5) as sock:
        sock.settimeout(5)
        assert b"Login:" in sock.recv(256)


def test_telnet_decoy_log_lines_are_valid_json(telnet_decoy):
    converse(telnet_decoy.port, [b"u\r\n", b"p\r\n", b"help\r\n", b"exit\r\n"])
    wait_for_event(telnet_decoy.log_path, "telnet_connection_closed")

    for line in telnet_decoy.log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            assert set(record) == {"timestamp", "source", "event_type", "details"}


def test_telnet_decoy_rejects_bad_arguments(native_dir):
    for argv in (["--port", "0"], ["--port", "99999"], ["--max-clients", "0"], ["--bogus"]):
        result = subprocess.run(
            [str(native_dir / "fake_telnet"), *argv], capture_output=True, timeout=30, check=False
        )
        assert result.returncode == 2, f"{argv} should be rejected"


def test_telnet_decoy_help_exits_zero(native_dir):
    result = subprocess.run(
        [str(native_dir / "fake_telnet"), "--help"], capture_output=True, timeout=30, check=False
    )

    assert result.returncode == 0
    assert b"--capture-credentials" in result.stdout


# -- SSH banner -------------------------------------------------------------


def test_ssh_decoy_sends_an_ssh_identification_string(ssh_decoy):
    with socket.create_connection(("127.0.0.1", ssh_decoy.port), timeout=5) as sock:
        sock.settimeout(5)
        banner = sock.recv(256)

    assert banner.startswith(b"SSH-2.0-")


def test_ssh_decoy_serves_a_fake_shell(ssh_decoy):
    transcript = converse(ssh_decoy.port, [b"root\r\n", b"toor\r\n", b"status\r\n", b"exit\r\n"])

    assert b"rtu358#" in transcript
    assert b"Modbus ONLINE" in transcript
    assert b"logout" in transcript


def test_ssh_decoy_redacts_the_password_by_default(ssh_decoy):
    converse(ssh_decoy.port, [b"root\r\n", b"Passw0rd\r\n", b"exit\r\n"])

    details = wait_for_event(ssh_decoy.log_path, "login_attempt")["details"]

    assert details["username"] == "root"
    assert details["password_length"] == len("Passw0rd")
    assert details["credentials_captured"] == 0
    assert "password" not in details
    assert "Passw0rd" not in ssh_decoy.log_path.read_text(encoding="utf-8")


def test_ssh_decoy_records_a_real_client_identification_string(ssh_decoy):
    """A genuine SSH client sends its own banner then waits for key exchange."""
    with socket.create_connection(("127.0.0.1", ssh_decoy.port), timeout=10) as sock:
        sock.settimeout(10)
        sock.recv(256)
        sock.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
        time.sleep(0.6)

    event = wait_for_event(ssh_decoy.log_path, "ssh_banner_peer_identification", timeout=8)
    assert "OpenSSH" in event["details"]["first_line"]


def test_ssh_decoy_notes_that_it_performs_no_key_exchange(ssh_decoy):
    with socket.create_connection(("127.0.0.1", ssh_decoy.port), timeout=5) as sock:
        sock.settimeout(5)
        sock.recv(256)

    event = wait_for_event(ssh_decoy.log_path, "ssh_banner_connection")
    assert "no key exchange" in event["details"]["note"]


def test_ssh_decoy_bounds_an_overlong_line(ssh_decoy):
    """An over-long line ends the session instead of buffering without limit."""
    with socket.create_connection(("127.0.0.1", ssh_decoy.port), timeout=10) as sock:
        sock.settimeout(10)
        sock.recv(256)
        sock.sendall(b"B" * 4096 + b"\r\n")
        # Stay connected and drain until the decoy hangs up, so the close
        # reason reflects its decision rather than our disconnect.
        drain_until_closed(sock)

    event = wait_for_event(ssh_decoy.log_path, "ssh_banner_connection_closed")
    assert event["details"]["reason"] == "line_too_long"


def test_ssh_decoy_handles_concurrent_clients(ssh_decoy):
    results: list[bool] = []
    lock = threading.Lock()

    def probe() -> None:
        with socket.create_connection(("127.0.0.1", ssh_decoy.port), timeout=5) as sock:
            sock.settimeout(5)
            ok = sock.recv(64).startswith(b"SSH-2.0-")
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=probe) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert results == [True] * 4


def test_ssh_decoy_rejects_bad_arguments(native_dir):
    for argv in (["--port", "-1"], ["--timeout", "0"], ["--max-clients", "99999"]):
        result = subprocess.run(
            [str(native_dir / "fake_ssh"), *argv], capture_output=True, timeout=30, check=False
        )
        assert result.returncode == 2, f"{argv} should be rejected"


def test_ssh_decoy_help_documents_that_it_is_not_an_ssh_server(native_dir):
    result = subprocess.run(
        [str(native_dir / "fake_ssh"), "--help"], capture_output=True, timeout=30, check=False
    )

    assert result.returncode == 0
    assert b"SSH-banner" in result.stdout


def test_credential_capture_requires_an_explicit_flag(native_dir, tmp_path):
    """With --capture-credentials the password is stored; that is the opt-in."""
    decoy = DecoyProcess(
        native_dir / "fake_telnet",
        free_tcp_port(),
        tmp_path / "capture.jsonl",
        extra=["--capture-credentials"],
    )
    try:
        decoy.wait_until_listening()
        converse(decoy.port, [b"operator\r\n", b"opt3dIn!\r\n", b"exit\r\n"])
        details = wait_for_event(decoy.log_path, "login_attempt")["details"]
    finally:
        decoy.stop()

    assert details["credentials_captured"] == 1
    assert details["password"] == "opt3dIn!"
