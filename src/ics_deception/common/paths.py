"""Runtime path resolution.

Every path used at runtime (event logs, per-component stdout/stderr logs, the
fake PLC state file, the approved PCAP directory) is resolved through this
module so that a deployment can relocate all mutable state with a single
environment variable.

Nothing here creates directories at import time; directories are created
lazily by the code that actually writes to them.

Environment variables
---------------------
``ICS_DECEPTION_RUNTIME_DIR``
    Root directory for all mutable runtime state. Default: ``./runtime``.
``ICS_DECEPTION_EVENT_LOG``
    Full path to the JSONL event log. Default: ``<runtime>/events.jsonl``.
``ICS_DECEPTION_PCAP_DIR``
    Approved directory that PCAP replay is restricted to. Default: ``./data/pcaps``.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = [
    "ENV_EVENT_LOG",
    "ENV_PCAP_DIR",
    "ENV_RUNTIME_DIR",
    "component_log_path",
    "ensure_dir",
    "event_log_path",
    "pcap_dir",
    "plc_state_path",
    "runtime_dir",
]

ENV_RUNTIME_DIR = "ICS_DECEPTION_RUNTIME_DIR"
ENV_EVENT_LOG = "ICS_DECEPTION_EVENT_LOG"
ENV_PCAP_DIR = "ICS_DECEPTION_PCAP_DIR"

DEFAULT_RUNTIME_DIRNAME = "runtime"
DEFAULT_PCAP_DIRNAME = os.path.join("data", "pcaps")


def runtime_dir() -> Path:
    """Return the root directory for mutable runtime state."""
    override = os.environ.get(ENV_RUNTIME_DIR)
    if override:
        return Path(override).expanduser().resolve()
    return (Path.cwd() / DEFAULT_RUNTIME_DIRNAME).resolve()


def event_log_path() -> Path:
    """Return the path of the shared JSONL event log."""
    override = os.environ.get(ENV_EVENT_LOG)
    if override:
        return Path(override).expanduser().resolve()
    return runtime_dir() / "events.jsonl"


def component_log_path(name: str) -> Path:
    """Return the stdout/stderr log path for a managed component."""
    safe = "".join(ch if (ch.isalnum() or ch in "-_") else "_" for ch in name)
    return runtime_dir() / "components" / f"{safe}.log"


def plc_state_path() -> Path:
    """Return the path of the fake PLC state snapshot."""
    return runtime_dir() / "plc_state.json"


def pcap_dir() -> Path:
    """Return the only directory PCAP replay is allowed to read from."""
    override = os.environ.get(ENV_PCAP_DIR)
    if override:
        return Path(override).expanduser().resolve()
    return (Path.cwd() / DEFAULT_PCAP_DIRNAME).resolve()


def ensure_dir(path: Path) -> Path:
    """Create ``path`` (a directory) if missing and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path
