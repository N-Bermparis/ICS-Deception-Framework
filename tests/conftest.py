"""Shared pytest fixtures.

Every test that touches runtime state redirects it into a temporary directory,
so the suite never writes logs, state files or binaries into the repository.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from ics_deception.common.paths import ENV_EVENT_LOG, ENV_PCAP_DIR, ENV_RUNTIME_DIR

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runtime_dir(tmp_path, monkeypatch) -> Path:
    """Redirect all runtime paths into an isolated temporary directory."""
    target = tmp_path / "runtime"
    target.mkdir()
    monkeypatch.setenv(ENV_RUNTIME_DIR, str(target))
    monkeypatch.setenv(ENV_EVENT_LOG, str(target / "events.jsonl"))
    return target


@pytest.fixture
def event_log(runtime_dir) -> Path:
    """Path of the isolated JSONL event log."""
    return runtime_dir / "events.jsonl"


@pytest.fixture
def approved_pcap_dir(tmp_path, monkeypatch) -> Path:
    """An approved capture directory containing one placeholder capture."""
    target = tmp_path / "pcaps"
    target.mkdir()
    # Content is irrelevant: only path validation is exercised here.
    (target / "sample.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    monkeypatch.setenv(ENV_PCAP_DIR, str(target))
    return target


@pytest.fixture(scope="session")
def native_build(tmp_path_factory) -> Path:
    """Build the native binaries fresh, once per session, into a temp directory.

    Deliberately *not* reusing ``build/`` from the working tree: a stale binary
    there would silently make these tests exercise old C++ sources, which is
    exactly the kind of false pass that hides a regression. Building into a
    temporary directory also keeps compiled artifacts out of the deliverable.
    """
    import shutil
    import subprocess
    import sys

    if sys.platform.startswith("win"):
        pytest.skip("the native components require a POSIX build environment")
    make = shutil.which("make")
    compiler = shutil.which("g++") or shutil.which("clang++")
    if make is None or compiler is None:
        pytest.skip("no C++ toolchain available (need make and g++/clang++)")

    build_dir = tmp_path_factory.mktemp("native-build")
    result = subprocess.run(
        [make, "-C", str(REPO_ROOT / "src" / "native"), f"BUILD_DIR={build_dir}", "all"],
        capture_output=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"native build failed:\n{result.stderr.decode(errors='replace')}")
    return build_dir


def free_tcp_port() -> int:
    """Reserve and release an unprivileged loopback port, returning its number.

    Binding to port 0 lets the kernel pick a free ephemeral port. There is an
    inherent race between releasing it and the service binding it, but it is
    the standard approach and keeps the suite off privileged ports entirely.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
