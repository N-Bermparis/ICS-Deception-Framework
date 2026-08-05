"""Structured JSONL event logging.

Every Python component emits events through :class:`EventPublisher`, which
appends one JSON object per line to the shared event log. The same schema is
produced by the native C++ honeypots so that a single JSONL stream can be
ingested by downstream tooling.

Event schema::

    {
      "timestamp": "2026-01-01T12:00:00.000000+00:00",  # ISO 8601, UTC
      "source": "modbus_server",                        # emitting component
      "event_type": "modbus_request",                   # event discriminator
      "details": { ... }                                # free-form payload
    }

Security note: ``details`` routinely contains attacker-supplied data. Treat the
event log as untrusted input in any downstream parser or dashboard.
"""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ics_deception.common.paths import ensure_dir, event_log_path

__all__ = ["Event", "EventPublisher", "default_publisher", "emit", "utc_now_iso"]

#: Maximum number of characters kept for any single string value in ``details``.
#: Attacker-controlled payloads are truncated so the log cannot be inflated.
MAX_DETAIL_STRING = 512


def utc_now_iso() -> str:
    """Return the current UTC time as a timezone-aware ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _truncate(value: Any) -> Any:
    """Bound the size of attacker-influenced values before they are logged."""
    if isinstance(value, str) and len(value) > MAX_DETAIL_STRING:
        return value[:MAX_DETAIL_STRING] + "...[truncated]"
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[: MAX_DETAIL_STRING // 2]).hex()
    if isinstance(value, dict):
        return {k: _truncate(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_truncate(v) for v in value]
    return value


@dataclass
class Event:
    """A single structured event."""

    source: str
    event_type: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return the event as a plain dictionary in canonical field order."""
        data = asdict(self)
        return {
            "timestamp": data["timestamp"],
            "source": data["source"],
            "event_type": data["event_type"],
            "details": data["details"],
        }

    def to_json(self) -> str:
        """Serialise the event to a single JSON line (no embedded newlines)."""
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


class EventPublisher:
    """Thread-safe JSONL event writer.

    Parameters
    ----------
    source:
        Component name recorded in every event.
    log_path:
        Optional explicit log file. When omitted the path is resolved lazily on
        each emit via :func:`ics_deception.common.paths.event_log_path`, so that
        changing ``ICS_DECEPTION_EVENT_LOG`` takes effect without re-importing.
    echo:
        Also write each line to stdout. Useful when a component runs under the
        controller, which redirects stdout to a per-component log file.
    evidence:
        Optional post-quantum evidence sink (see
        :mod:`ics_deception.pqc_evidence.integration`). ``None`` — the default —
        keeps the historical unsigned behaviour exactly as it was, so every
        component works unchanged when evidence signing is disabled.
    """

    #: Shared across instances: multiple publishers write to the same file.
    _lock = threading.Lock()

    def __init__(
        self,
        source: str = "core",
        log_path: str | Path | None = None,
        echo: bool = True,
        evidence: Any | None = None,
    ) -> None:
        self.source = source
        self._log_path = Path(log_path) if log_path is not None else None
        self.echo = echo
        self.evidence = evidence

    @property
    def log_path(self) -> Path:
        """Resolve the destination log file for this publisher."""
        return self._log_path if self._log_path is not None else event_log_path()

    def build(self, event_type: str, **details: Any) -> Event:
        """Build (but do not write) an event with truncated detail values."""
        return Event(
            source=self.source,
            event_type=event_type,
            details={key: _truncate(value) for key, value in details.items()},
        )

    def emit(self, event_type: str, **details: Any) -> Event:
        """Append an event to the JSONL log and return it.

        When an evidence sink is attached it decides whether the raw line is
        written, a signed envelope is written, or both. A failure inside the
        evidence layer never prevents the plain event from being recorded — a
        deception sensor losing its telemetry is worse than losing its seal.
        """
        event = self.build(event_type, **details)
        line = event.to_json()
        path = self.log_path

        write_raw = True
        if self.evidence is not None:
            try:
                write_raw = self.evidence.handle(event)
            except Exception as exc:  # noqa: BLE001 - never lose telemetry
                print(f"evidence signing failed: {exc}", file=sys.stderr, flush=True)
                write_raw = True

        if write_raw:
            with self._lock:
                try:
                    ensure_dir(path.parent)
                    with open(path, "a", encoding="utf-8") as handle:
                        handle.write(line + "\n")
                except OSError as exc:  # pragma: no cover - disk/permission failure
                    print(f"event log write failed: {exc}", file=sys.stderr, flush=True)
        if self.echo:
            print(line, file=sys.stdout, flush=True)
        return event

    def info(self, message: str, **details: Any) -> Event:
        """Emit an ``info`` event."""
        details.setdefault("message", message)
        return self.emit("info", **details)

    def warning(self, message: str, **details: Any) -> Event:
        """Emit a ``warning`` event."""
        details.setdefault("message", message)
        return self.emit("warning", **details)

    def error(self, message: str, **details: Any) -> Event:
        """Emit an ``error`` event."""
        details.setdefault("message", message)
        return self.emit("error", **details)


#: Convenience publisher for callers that do not need their own source name.
default_publisher = EventPublisher(source="global")


def emit(event_type: str, **details: Any) -> Event:
    """Emit an event through :data:`default_publisher`."""
    return default_publisher.emit(event_type, **details)
