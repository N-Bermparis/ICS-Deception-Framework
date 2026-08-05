"""Wiring ``pqc_evidence`` into the framework's event publisher.

The honeypots stay ignorant of cryptography: they keep calling
``publisher.emit(...)``. An :class:`EvidenceSink` attached to the publisher
decides what happens to each event.

Modes
-----
``disabled`` (default)
    Nothing changes. Plain unsigned JSONL, no key required, no cryptographic
    backend loaded.
``sign``
    Each event is signed and durably appended to the evidence log. The raw line
    is not written to the normal event log.
``dual``
    Both are written — raw to the event log, signed to the evidence log.
``verify-only``
    Nothing is signed. For a collector process that verifies evidence produced
    elsewhere.

A signing key is **never created implicitly**. If a mode other than ``disabled``
is configured without a usable key, construction fails loudly rather than
silently producing unsigned output that looks signed.

Persistence is transactional: :class:`~ics_deception.pqc_evidence.signer.EvidenceSigner`
appends inside the same lock that allocates the sequence, so this sink never
writes the evidence file itself and cannot reorder records.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import EvidenceMode
from ics_deception.pqc_evidence.crypto_backend import BackendError, select_backend
from ics_deception.pqc_evidence.signer import EvidenceSigner, SignerError, load_private_key

__all__ = [
    "ENV_EVIDENCE_LOG",
    "ENV_EVIDENCE_MODE",
    "ENV_KEY_ID",
    "ENV_NODE_ID",
    "ENV_PRIVATE_KEY",
    "ENV_STATE",
    "EvidenceMetrics",
    "EvidenceSink",
    "EvidenceSinkConfig",
    "sink_from_env",
]

ENV_EVIDENCE_MODE = "ICS_PQC_EVIDENCE_MODE"
ENV_NODE_ID = "ICS_PQC_NODE_ID"
ENV_KEY_ID = "ICS_PQC_KEY_ID"
ENV_PRIVATE_KEY = "ICS_PQC_PRIVATE_KEY"
ENV_EVIDENCE_LOG = "ICS_PQC_EVIDENCE_LOG"
ENV_STATE = "ICS_PQC_STATE"
ENV_BACKEND = "ICS_PQC_BACKEND"

#: Maximum canonical size of a single event body accepted for signing. Larger
#: events are replaced by bounded metadata plus a digest, so one huge payload
#: cannot bloat the signed chain.
MAX_SIGNED_EVENT_BYTES = 16 * 1024


@dataclass
class EvidenceMetrics:
    """Accurate, concurrency-safe counters for one sink.

    Each counter is incremented only when the operation it names has actually
    happened. An event is not "signed" until the signature exists, and not
    "persisted" until the transaction has committed.
    """

    received: int = 0
    signed: int = 0
    persisted: int = 0
    rejected_before_signing: int = 0
    signing_failures: int = 0
    persistence_failures: int = 0
    backend_unavailable: int = 0
    state_recoveries: int = 0
    verification_successes: int = 0
    verification_failures: int = 0
    archive_failures: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def increment(self, name: str, amount: int = 1) -> None:
        """Atomically add to one counter."""
        with self._lock:
            setattr(self, name, getattr(self, name) + amount)

    def snapshot(self) -> dict[str, int]:
        """Return a consistent copy of every counter."""
        with self._lock:
            return {
                "received": self.received,
                "signed": self.signed,
                "persisted": self.persisted,
                "rejected_before_signing": self.rejected_before_signing,
                "signing_failures": self.signing_failures,
                "persistence_failures": self.persistence_failures,
                "backend_unavailable": self.backend_unavailable,
                "state_recoveries": self.state_recoveries,
                "verification_successes": self.verification_successes,
                "verification_failures": self.verification_failures,
                "archive_failures": self.archive_failures,
            }


@dataclass
class EvidenceSinkConfig:
    """Configuration for an :class:`EvidenceSink`."""

    mode: str = EvidenceMode.DISABLED
    node_id: str = ""
    key_id: str = ""
    private_key_path: str = ""
    evidence_log: str = "runtime/pqc/evidence.jsonl"
    state_path: str = "runtime/pqc/state.json"
    backend: str | None = None
    allow_test_backend: bool = False
    lock_timeout: float = 10.0

    def validate(self) -> None:
        """Raise :class:`ValueError` if this configuration cannot work."""
        if self.mode not in EvidenceMode.ALL:
            raise ValueError(
                f"unknown evidence mode {self.mode!r}; expected one of {EvidenceMode.ALL}"
            )
        if self.lock_timeout <= 0:
            raise ValueError("lock_timeout must be greater than zero")
        if self.mode in (EvidenceMode.SIGN, EvidenceMode.DUAL):
            missing = [
                name
                for name, value in (
                    (ENV_NODE_ID, self.node_id),
                    (ENV_KEY_ID, self.key_id),
                    (ENV_PRIVATE_KEY, self.private_key_path),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    f"evidence mode {self.mode!r} requires {', '.join(missing)}; "
                    "no signing key is ever created automatically"
                )


class EvidenceSink:
    """Attaches to an ``EventPublisher`` and seals events as they are emitted.

    :meth:`handle` returns whether the publisher should still write the plain
    unsigned line, which is what distinguishes ``sign`` from ``dual``.
    """

    def __init__(self, config: EvidenceSinkConfig) -> None:
        config.validate()
        self.config = config
        self.mode = config.mode
        self.metrics = EvidenceMetrics()
        self._signer: EvidenceSigner | None = None
        self._evidence_path = Path(config.evidence_log)
        self._last_error: str | None = None

        if self.mode in (EvidenceMode.SIGN, EvidenceMode.DUAL):
            self._signer = self._build_signer()

    def _build_signer(self) -> EvidenceSigner:
        config = self.config
        try:
            private_key = load_private_key(config.private_key_path)
        except SignerError:
            self.metrics.increment("backend_unavailable")
            raise
        try:
            backend = select_backend(
                name=config.backend,
                allow_test_backend=config.allow_test_backend,
                for_private_key=private_key,
            )
        except BackendError as exc:
            self.metrics.increment("backend_unavailable")
            raise SignerError(
                f"evidence signing is enabled but no usable backend was found: {exc}"
            ) from exc
        signer = EvidenceSigner(
            node_id=config.node_id,
            key_id=config.key_id,
            private_key=private_key,
            state_path=config.state_path,
            evidence_path=config.evidence_log,
            backend=backend,
            lock_timeout=config.lock_timeout,
        )
        # Opening the store once here surfaces an unrecoverable state/log
        # divergence at startup rather than on the first attacker interaction.
        with signer.store() as store:
            recovery = store.last_recovery
            if recovery and recovery.action not in ("none", ""):
                self.metrics.increment("state_recoveries")
        return signer

    # -- introspection -----------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Whether this sink signs anything."""
        return self._signer is not None

    @property
    def backend_name(self) -> str:
        """Backend performing the signatures, or an empty string."""
        return self._signer.backend_name if self._signer else ""

    def status(self) -> dict[str, Any]:
        """Return a status snapshot. Never contains key material."""
        status: dict[str, Any] = {
            "mode": self.mode,
            "enabled": self.enabled,
            "node_id": self.config.node_id,
            "key_id": self.config.key_id,
            "backend": self.backend_name,
            "evidence_log": str(self._evidence_path),
            "last_error": self._last_error,
            "metrics": self.metrics.snapshot(),
        }
        if self._signer is not None:
            try:
                chain = self._signer.status()
            except Exception as exc:  # noqa: BLE001 - status must never raise
                status["chain_error"] = str(exc)
            else:
                status["chain"] = {
                    "last_sequence": chain.get("last_sequence"),
                    "last_event_hash": chain.get("last_event_hash"),
                    "journal_present": chain.get("journal_present"),
                    "evidence_bytes": chain.get("evidence_bytes"),
                    "real_pqc": chain.get("real_pqc"),
                }
        return status

    # -- the hot path ------------------------------------------------------

    def bound_event(self, event: Any) -> dict[str, Any]:
        """Convert an ``Event`` into a bounded dict suitable for signing.

        Very large payloads are not signed verbatim: they are replaced by their
        size and SHA3-256 digest, so the chain stays small while the original
        remains checkable against the digest. The publisher already truncates
        individual long strings; this is the second bound, catching events made
        large by *many* fields.
        """
        payload = {
            "source": event.source,
            "event_type": event.event_type,
            **event.details,
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)
        if len(encoded) <= MAX_SIGNED_EVENT_BYTES:
            return json.loads(encoded)
        digest = hashlib.sha3_256(encoded.encode("utf-8")).hexdigest()
        return {
            "source": event.source,
            "event_type": event.event_type,
            "payload_truncated": True,
            "payload_bytes": len(encoded),
            "payload_sha3_256": digest,
        }

    def handle(self, event: Any) -> bool:
        """Seal one event. Returns whether the raw line should still be written.

        Counters advance only as each stage genuinely completes. A failure here
        is recorded and re-raised to the publisher, which falls back to writing
        the plain event — losing telemetry is worse than losing a seal.
        """
        self.metrics.increment("received")
        if self._signer is None:
            # disabled / verify-only: preserve the original behaviour exactly.
            return True

        try:
            bounded = self.bound_event(event)
        except Exception as exc:  # noqa: BLE001 - malformed event, not a crash
            self.metrics.increment("rejected_before_signing")
            self._last_error = f"event could not be prepared for signing: {exc}"
            raise SignerError(self._last_error) from exc

        try:
            record = self._signer.sign_event(bounded, timestamp=event.timestamp)
        except BackendError as exc:
            self.metrics.increment("backend_unavailable")
            self.metrics.increment("signing_failures")
            self._last_error = f"backend failure: {exc}"
            raise
        except SignerError as exc:
            self.metrics.increment("signing_failures")
            self._last_error = str(exc)
            raise
        except Exception as exc:  # noqa: BLE001 - store/IO failures
            # The transaction rolled back: nothing was committed, so this is a
            # persistence failure rather than a signing failure.
            self.metrics.increment("persistence_failures")
            self._last_error = str(exc)
            raise

        # sign_event only returns after the record is durably appended and the
        # state committed, so both counters advance together and truthfully.
        self.metrics.increment("signed")
        self.metrics.increment("persisted")
        self._last_error = None
        _ = record

        return self.mode == EvidenceMode.DUAL


def sink_from_env(environ: dict[str, str] | None = None) -> EvidenceSink | None:
    """Build a sink from environment variables, or ``None`` when disabled.

    Reading configuration from the environment keeps the honeypots free of any
    evidence-specific command-line surface, and defaulting to ``disabled`` means
    an unconfigured deployment behaves exactly as it always has.

    Raises :class:`SignerError` when signing is explicitly enabled but cannot
    start. It never degrades quietly to unsigned output.
    """
    env = environ if environ is not None else dict(os.environ)
    mode = env.get(ENV_EVIDENCE_MODE, EvidenceMode.DISABLED).strip().lower()
    if mode in ("", EvidenceMode.DISABLED):
        return None

    config = EvidenceSinkConfig(
        mode=mode,
        node_id=env.get(ENV_NODE_ID, ""),
        key_id=env.get(ENV_KEY_ID, ""),
        private_key_path=env.get(ENV_PRIVATE_KEY, ""),
        evidence_log=env.get(ENV_EVIDENCE_LOG, "runtime/pqc/evidence.jsonl"),
        state_path=env.get(ENV_STATE, "runtime/pqc/state.json"),
        backend=env.get(ENV_BACKEND) or None,
    )
    try:
        return EvidenceSink(config)
    except (ValueError, SignerError, BackendError) as exc:
        raise SignerError(
            f"{ENV_EVIDENCE_MODE}={mode!r} is set but evidence signing cannot start: {exc}"
        ) from exc
