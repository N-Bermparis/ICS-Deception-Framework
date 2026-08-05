"""The one way every service creates its event publisher.

Before this existed, each service constructed ``EventPublisher(...)`` directly
and nothing ever attached an evidence sink. The PQC layer was reachable only by
handing a sink in from a test — so the documented environment variables did
nothing in a real deployment. This factory is the fix: one place that reads the
configuration, builds the sink, attaches it, and is used by every service.

Behaviour:

* **Evidence disabled (default).** Returns a plain publisher. No cryptographic
  import happens, no key is touched, and logging is byte-for-byte what it was.
* **Evidence enabled.** Builds the configured sink and attaches it. If the mode
  is set but the key, state, node identity or backend is unusable, this raises
  :class:`~ics_deception.pqc_evidence.signer.SignerError` — loudly, at startup,
  rather than degrading to unsigned output that looks signed.
* **A signing key is never created here**, or anywhere else automatically.

The import of :mod:`ics_deception.pqc_evidence` is deferred until a mode other
than ``disabled`` is configured, so the framework keeps running on a node that
has no post-quantum dependencies installed at all.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ics_deception.common.events import EventPublisher

__all__ = [
    "ENV_EVIDENCE_MODE",
    "create_event_publisher",
    "evidence_status",
    "reset_shared_sink",
]

ENV_EVIDENCE_MODE = "ICS_PQC_EVIDENCE_MODE"

#: One sink per process. Every publisher shares it, so all of a service's
#: events land on one chain in one file, and the single-writer lock is taken
#: once rather than fought over by several sinks in the same process.
_SHARED_SINK: Any | None = None
_SHARED_SINK_READY = False


def reset_shared_sink() -> None:
    """Forget the cached sink so the next call re-reads the environment.

    Used by tests, and by a controller that reloads its configuration.
    """
    global _SHARED_SINK, _SHARED_SINK_READY
    _SHARED_SINK = None
    _SHARED_SINK_READY = False


def _evidence_mode() -> str:
    return os.environ.get(ENV_EVIDENCE_MODE, "disabled").strip().lower()


def _shared_sink() -> Any | None:
    """Build (once) and return the process-wide evidence sink, or ``None``."""
    global _SHARED_SINK, _SHARED_SINK_READY
    if _SHARED_SINK_READY:
        return _SHARED_SINK

    mode = _evidence_mode()
    if mode in ("", "disabled"):
        _SHARED_SINK, _SHARED_SINK_READY = None, True
        return None

    # Deferred import: a node with no PQC dependencies must still start.
    from ics_deception.pqc_evidence.integration import sink_from_env

    _SHARED_SINK = sink_from_env()
    _SHARED_SINK_READY = True
    return _SHARED_SINK


def create_event_publisher(
    source: str,
    log_path: str | Path | None = None,
    echo: bool = True,
) -> EventPublisher:
    """Create an event publisher with PQC evidence attached when configured.

    Parameters
    ----------
    source:
        Component name recorded in every event.
    log_path:
        Optional explicit unsigned event log. When omitted the shared log path
        is resolved lazily on each emit.
    echo:
        Also write each line to stdout.

    Raises
    ------
    ics_deception.pqc_evidence.signer.SignerError
        Signing was explicitly enabled but cannot start. Never silently
        downgraded.
    """
    return EventPublisher(
        source=source, log_path=log_path, echo=echo, evidence=_shared_sink()
    )


def evidence_status() -> dict[str, Any]:
    """Return the evidence layer's status for ``/status`` and diagnostics.

    Contains no private key material — only the configured identifiers, the
    backend name, chain position and counters.
    """
    mode = _evidence_mode()
    if mode in ("", "disabled"):
        return {"mode": "disabled", "enabled": False}
    try:
        sink = _shared_sink()
    except Exception as exc:  # noqa: BLE001 - status must never raise
        return {"mode": mode, "enabled": False, "error": str(exc)}
    if sink is None:
        return {"mode": mode, "enabled": False}
    return sink.status()
