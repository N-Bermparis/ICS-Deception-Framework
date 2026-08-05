"""Evidence verifier: check one signed record against the registry and chain.

Verification answers three separate questions, and reports each independently
so an operator can tell *how* evidence failed:

1. **Is the record well formed?** Strict envelope validation.
2. **Was the key allowed to sign this?** Registry lookup: known node, known key,
   not revoked, not disabled, within its activation/expiry window, right
   algorithm.
3. **Does the cryptography hold?** ``event_hash`` recomputation, chain linkage,
   and the ML-DSA signature itself.

All findings are collected; verification does not stop at the first problem,
because "invalid signature *and* previous-hash mismatch" is a materially
different story from either alone.

Alert vocabulary
----------------
Every failure maps to one of the stable ``pqc_*`` codes in :data:`ALERTS`, so
downstream tooling can match on codes rather than on message text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ics_deception.pqc_evidence import EvidenceError
from ics_deception.pqc_evidence.crypto_backend import (
    BackendError,
    CryptoBackend,
    select_backend,
)
from ics_deception.pqc_evidence.event_chain import (
    FIRST_SEQUENCE,
    ChainPosition,
    compute_event_hash,
    genesis_previous_hash,
)
from ics_deception.pqc_evidence.key_registry import KeyRegistry
from ics_deception.pqc_evidence.models import (
    MAX_EVIDENCE_BYTES,
    EvidenceValidationError,
    SignedEvent,
    parse_signed_event_json,
)

#: Defensible upper bound on any configured record limit. Well above a real
#: record (a 3.3 KiB ML-DSA-65 signature plus a rich event) and far below a size
#: that would let one line exhaust memory.
MAX_EVIDENCE_BYTES_CEILING = 16 * 1024 * 1024

__all__ = [
    "ALERTS",
    "EvidenceVerifier",
    "VerificationResult",
    "VerifierError",
]

#: The complete set of structured alerts this package can raise.
ALERTS = (
    "pqc_invalid_signature",
    "pqc_event_hash_mismatch",
    "pqc_previous_hash_mismatch",
    "pqc_sequence_gap",
    "pqc_duplicate_sequence",
    "pqc_replayed_event",
    "pqc_unknown_node",
    "pqc_unknown_key",
    "pqc_revoked_key",
    "pqc_expired_key",
    "pqc_chain_reset",
    "pqc_unsupported_algorithm",
    "pqc_malformed_evidence",
    "pqc_oversized_evidence",
)

#: Envelope validation reasons mapped onto alert codes.
_REASON_TO_ALERT = {
    "malformed_evidence": "pqc_malformed_evidence",
    "oversized_evidence": "pqc_oversized_evidence",
    "unsupported_algorithm": "pqc_unsupported_algorithm",
    "unsupported_format_version": "pqc_malformed_evidence",
}


class VerifierError(EvidenceError):
    """The verifier itself could not run (not an evidence failure)."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


@dataclass
class VerificationResult:
    """The outcome of verifying one evidence record."""

    valid: bool
    node_id: str = ""
    sequence: int = 0
    event_hash: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    verified_at: str = field(default_factory=_utc_now)
    #: Human-readable explanations, aligned with ``errors`` where possible.
    details: list[str] = field(default_factory=list)
    key_id: str = ""

    def add_error(self, alert: str, detail: str = "") -> None:
        """Record a failure alert."""
        if alert not in self.errors:
            self.errors.append(alert)
        if detail:
            self.details.append(detail)
        self.valid = False

    def add_warning(self, alert: str, detail: str = "") -> None:
        """Record a non-fatal observation. Warnings never clear ``valid``."""
        if alert not in self.warnings:
            self.warnings.append(alert)
        if detail:
            self.details.append(detail)

    def to_dict(self) -> dict[str, Any]:
        """Return the structured report."""
        return {
            "valid": self.valid,
            "node_id": self.node_id,
            "sequence": self.sequence,
            "event_hash": self.event_hash,
            "key_id": self.key_id,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "details": list(self.details),
            "verified_at": self.verified_at,
        }


class EvidenceVerifier:
    """Verifies signed evidence against a trusted-key registry."""

    def __init__(
        self,
        registry: KeyRegistry,
        backend: CryptoBackend | None = None,
        allow_test_backend: bool = False,
        max_record_bytes: int = MAX_EVIDENCE_BYTES,
    ) -> None:
        if max_record_bytes <= 0:
            raise VerifierError("max_record_bytes must be greater than zero")
        if max_record_bytes > MAX_EVIDENCE_BYTES_CEILING:
            raise VerifierError(
                f"max_record_bytes must not exceed {MAX_EVIDENCE_BYTES_CEILING}"
            )
        self.registry = registry
        self._backend = backend
        self._allow_test_backend = allow_test_backend
        #: Enforced on every record this verifier parses, from any entry point.
        self.max_record_bytes = max_record_bytes

    def backend_for(self, algorithm: str) -> CryptoBackend:
        """Return a backend able to verify ``algorithm``."""
        if self._backend is not None:
            return self._backend
        return select_backend(
            algorithm=algorithm, allow_test_backend=self._allow_test_backend
        )

    # -- single record -----------------------------------------------------

    def verify_line(self, line: str | bytes) -> tuple[VerificationResult, SignedEvent | None]:
        """Parse and verify one JSONL record.

        A record that fails parsing yields a result with
        ``pqc_malformed_evidence`` (or ``pqc_oversized_evidence``) and no event.
        """
        # The configured limit is applied here, so every caller — single event,
        # stream, CLI, archive, controller — gets the same bound. Oversized
        # input is rejected on the raw bytes, before any structural parsing.
        try:
            event = parse_signed_event_json(line, max_bytes=self.max_record_bytes)
        except EvidenceValidationError as exc:
            result = VerificationResult(valid=False)
            result.add_error(
                _REASON_TO_ALERT.get(exc.reason, "pqc_malformed_evidence"), str(exc)
            )
            return result, None
        return self.verify_event(event), event

    def verify_event(
        self, event: SignedEvent, position: ChainPosition | None = None
    ) -> VerificationResult:
        """Verify one already-parsed record, optionally against a chain cursor."""
        result = VerificationResult(
            valid=True,
            node_id=event.node_id,
            sequence=event.sequence,
            event_hash=event.event_hash,
            key_id=event.key_id,
        )

        self._check_event_hash(event, result)
        self._check_key(event, result)
        self._check_signature(event, result)
        if position is not None:
            self._check_chain(event, position, result)
        return result

    # -- individual checks -------------------------------------------------

    def _check_event_hash(self, event: SignedEvent, result: VerificationResult) -> None:
        recomputed = compute_event_hash(event)
        if recomputed != event.event_hash:
            result.add_error(
                "pqc_event_hash_mismatch",
                f"event_hash is {event.event_hash} but the content hashes to {recomputed}; "
                "the event body or a header field was modified after signing",
            )

    def _check_key(self, event: SignedEvent, result: VerificationResult) -> None:
        usability = self.registry.check_usable(
            key_id=event.key_id,
            node_id=event.node_id,
            at=event.timestamp,
            algorithm=event.signature_algorithm,
        )
        if not usability.usable:
            for alert in usability.problems:
                result.add_error(alert, "")
            if usability.detail:
                result.details.append(usability.detail)

    def _check_signature(self, event: SignedEvent, result: VerificationResult) -> None:
        record = self.registry.get(event.key_id)
        if record is None:
            # The key problem was already reported by _check_key; without a
            # public key the signature simply cannot be checked.
            result.add_error(
                "pqc_invalid_signature",
                f"signature cannot be verified: key {event.key_id!r} is not in the registry",
            )
            return
        try:
            public_key = record.public_key_bytes
        except Exception as exc:
            result.add_error("pqc_invalid_signature", f"registry public key is unusable: {exc}")
            return

        try:
            backend = self.backend_for(event.signature_algorithm)
        except BackendError as exc:
            raise VerifierError(
                f"cannot verify {event.signature_algorithm}: {exc.detail}"
            ) from exc

        try:
            ok = backend.verify(
                public_key,
                event.signing_payload(),
                event.signature_bytes,
                event.signature_algorithm,
            )
        except BackendError as exc:
            raise VerifierError(f"verification backend failed: {exc.detail}") from exc
        if not ok:
            result.add_error(
                "pqc_invalid_signature",
                f"ML-DSA signature does not verify against key {event.key_id!r} "
                f"(fingerprint {record.fingerprint})",
            )

    def _check_chain(
        self, event: SignedEvent, position: ChainPosition, result: VerificationResult
    ) -> None:
        """Check sequence continuity and previous-hash linkage."""
        expected_sequence = position.next_sequence

        if event.sequence < expected_sequence:
            if event.sequence <= position.last_sequence:
                result.add_error(
                    "pqc_duplicate_sequence",
                    f"sequence {event.sequence} was already seen for node {event.node_id!r} "
                    f"(chain is at {position.last_sequence})",
                )
        elif event.sequence > expected_sequence:
            missing = event.sequence - expected_sequence
            result.add_error(
                "pqc_sequence_gap",
                f"{missing} event(s) missing between sequence {position.last_sequence} "
                f"and {event.sequence} for node {event.node_id!r}",
            )

        if event.sequence == FIRST_SEQUENCE:
            expected_previous = genesis_previous_hash(event.node_id)
            if position.last_sequence > 0:
                result.add_error(
                    "pqc_chain_reset",
                    f"node {event.node_id!r} restarted its chain at sequence 1 while the "
                    f"previous chain was at {position.last_sequence}",
                )
            if event.previous_event_hash != expected_previous:
                result.add_error(
                    "pqc_previous_hash_mismatch",
                    f"genesis previous_event_hash is {event.previous_event_hash} but this node's "
                    f"derived genesis value is {expected_previous}; the record is not a valid "
                    "genesis for this node",
                )
        elif position.last_event_hash is not None:
            if event.previous_event_hash != position.last_event_hash:
                result.add_error(
                    "pqc_previous_hash_mismatch",
                    f"previous_event_hash is {event.previous_event_hash} but the preceding "
                    f"event hashes to {position.last_event_hash}; events were reordered, "
                    "replaced or spliced from another chain",
                )
