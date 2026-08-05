"""The versioned signed-event envelope and its strict validation.

Every field is validated before it is trusted, because evidence arrives from
untrusted places: a compromised node, a hostile file, a replayed stream. Parsing
must never crash the signer, verifier, collector, CLI, controller or archive
tools — malformed input always becomes a structured :class:`EvidenceValidationError`.

Envelope shape (``format_version`` 1.0)::

    {
      "format_version": "1.0",
      "node_id": "rpi-honeypot-01",
      "sequence": 154,
      "timestamp": "2026-08-05T18:15:00.000000Z",
      "previous_event_hash": "<64 hex chars>",
      "event_hash": "<64 hex chars>",
      "event": { ... },
      "signature_algorithm": "ML-DSA-65",
      "hash_algorithm": "SHA3-256",
      "key_id": "rpi-honeypot-01-2026-01",
      "signature": "<base64>"
    }
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any

from ics_deception.pqc_evidence import (
    DEFAULT_HASH_ALGORITHM,
    DEFAULT_SIGNATURE_ALGORITHM,
    EVIDENCE_FORMAT_VERSION,
    EvidenceError,
)
from ics_deception.pqc_evidence.canonicalizer import (
    CanonicalizationError,
    canonical_bytes,
    check_canonicalizable,
    normalize_timestamp,
)

__all__ = [
    "ENVELOPE_FIELDS",
    "EvidenceValidationError",
    "MAX_EVENT_DEPTH",
    "MAX_EVIDENCE_BYTES",
    "MAX_NODE_ID_LENGTH",
    "SUPPORTED_FORMAT_VERSIONS",
    "SUPPORTED_HASH_ALGORITHMS",
    "SUPPORTED_SIGNATURE_ALGORITHMS",
    "SignedEvent",
    "parse_signed_event",
    "parse_signed_event_json",
]

#: Envelope versions this build understands.
SUPPORTED_FORMAT_VERSIONS = frozenset({"1.0"})

#: Signature algorithms this build accepts. ML-DSA only: no classical fallback.
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})

#: Hash algorithms this build accepts for the event chain.
SUPPORTED_HASH_ALGORITHMS = frozenset({"SHA3-256"})

#: Maximum serialized size of one evidence record, in bytes. Generous enough
#: for a 3.3 KiB ML-DSA-65 signature plus a rich event, small enough that a
#: hostile line cannot exhaust memory. Override per call site if needed.
MAX_EVIDENCE_BYTES = 262_144

#: Maximum serialized size of the nested ``event`` object.
MAX_EVENT_BYTES = 65_536

#: Maximum nesting depth inside the nested ``event`` object.
MAX_EVENT_DEPTH = 16

#: Maximum length of a node identifier or key identifier.
MAX_NODE_ID_LENGTH = 128

#: Node and key identifiers: printable, filesystem-safe, no path separators.
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

#: Lowercase hexadecimal SHA3-256 digest.
_SHA3_256_HEX = re.compile(r"^[0-9a-f]{64}$")

#: The complete, closed set of envelope fields. Unknown fields are rejected:
#: an unrecognised field could otherwise carry unsigned data that a downstream
#: consumer mistakes for verified content.
ENVELOPE_FIELDS = (
    "format_version",
    "node_id",
    "sequence",
    "timestamp",
    "previous_event_hash",
    "event_hash",
    "event",
    "signature_algorithm",
    "hash_algorithm",
    "key_id",
    "signature",
)

#: Fields excluded when computing ``event_hash``.
_HASH_EXCLUDED = frozenset({"event_hash", "signature"})

#: Field excluded when computing the signing payload.
_SIGNATURE_EXCLUDED = frozenset({"signature"})


class EvidenceValidationError(EvidenceError):
    """An evidence record is structurally invalid.

    ``reason`` carries a stable machine-readable code so callers can map it to
    an alert without string matching on the message.
    """

    def __init__(self, message: str, reason: str = "malformed_evidence") -> None:
        super().__init__(message)
        self.reason = reason


def _require(condition: bool, message: str, reason: str = "malformed_evidence") -> None:
    if not condition:
        raise EvidenceValidationError(message, reason)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects duplicate JSON object keys.

    ``json.loads`` silently keeps the last value for a repeated key, so
    ``{"sequence":1,"sequence":999}`` would parse as 999 while a naive verifier
    that re-reads the raw text might see 1. Rejecting duplicates outright
    removes that whole class of confusion.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise EvidenceValidationError(
                f"duplicate JSON key {key!r} in evidence record", "malformed_evidence"
            )
        seen.add(key)
    return dict(pairs)


def _safe_excerpt(value: Any, limit: int = 24) -> str:
    """Render untrusted input for an error message, bounded and escaped.

    Error messages travel into logs and dashboards, so attacker-controlled text
    is truncated and ASCII-escaped rather than echoed verbatim.
    """
    text = value if isinstance(value, str) else repr(value)
    clipped = text[:limit]
    rendered = clipped.encode("unicode_escape").decode("ascii", errors="replace")
    return rendered + ("..." if len(text) > limit else "")


def _validate_identifier(value: Any, field_name: str) -> str:
    _require(isinstance(value, str), f"{field_name} must be a string")
    _require(bool(value), f"{field_name} must not be empty")
    _require(
        len(value) <= MAX_NODE_ID_LENGTH,
        f"{field_name} exceeds {MAX_NODE_ID_LENGTH} characters",
    )
    _require(
        _ID_PATTERN.match(value) is not None,
        f"{field_name} '{_safe_excerpt(value)}' contains illegal characters "
        "(allowed: letters, digits, '.', '_', ':', '-')",
    )
    return value


def _validate_hash(value: Any, field_name: str) -> str:
    _require(isinstance(value, str), f"{field_name} must be a string")
    _require(
        _SHA3_256_HEX.match(value) is not None,
        f"{field_name} must be 64 lowercase hexadecimal characters (SHA3-256)",
    )
    return value


def _validate_sequence(value: Any) -> int:
    # bool is a subclass of int; True would otherwise pass as sequence 1.
    _require(isinstance(value, int) and not isinstance(value, bool), "sequence must be an integer")
    _require(value >= 1, "sequence must be a positive integer starting at 1")
    _require(value <= 2**63 - 1, "sequence is out of range")
    return value


def _validate_event(value: Any) -> dict[str, Any]:
    _require(isinstance(value, dict), "event must be a JSON object")
    try:
        check_canonicalizable(value)
    except CanonicalizationError as exc:
        raise EvidenceValidationError(f"event is not canonicalizable: {exc}") from exc

    from ics_deception.pqc_evidence.canonicalizer import canonical_bytes as _cb

    encoded = _cb(value)
    _require(
        len(encoded) <= MAX_EVENT_BYTES,
        f"event is {len(encoded)} bytes, exceeding the {MAX_EVENT_BYTES} byte limit",
        "oversized_evidence",
    )
    _require(_depth(value) <= MAX_EVENT_DEPTH, f"event nests deeper than {MAX_EVENT_DEPTH} levels")
    return value


def _depth(value: Any, level: int = 1) -> int:
    if isinstance(value, dict):
        return max((_depth(v, level + 1) for v in value.values()), default=level)
    if isinstance(value, (list, tuple)):
        return max((_depth(v, level + 1) for v in value), default=level)
    return level


def _validate_signature(value: Any) -> bytes:
    _require(isinstance(value, str), "signature must be a base64 string")
    _require(bool(value), "signature must not be empty")
    try:
        # validate=True rejects whitespace and non-alphabet characters instead
        # of silently discarding them, which would let two different texts
        # decode to the same signature.
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EvidenceValidationError(f"signature is not valid base64: {exc}") from exc
    _require(bool(raw), "signature decodes to zero bytes")
    return raw


@dataclass(frozen=True)
class SignedEvent:
    """A validated signed-event envelope.

    Construct through :func:`parse_signed_event` (untrusted input) or
    :meth:`build_unsigned` (local signing path). Direct construction skips
    validation and is for internal use only.
    """

    format_version: str
    node_id: str
    sequence: int
    timestamp: str
    previous_event_hash: str
    event_hash: str
    event: dict[str, Any]
    signature_algorithm: str
    hash_algorithm: str
    key_id: str
    signature: str = ""
    signature_bytes: bytes = field(default=b"", repr=False, compare=False)

    # -- serialisation ----------------------------------------------------

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        """Return the envelope as a plain dict in canonical field order."""
        data: dict[str, Any] = {
            "format_version": self.format_version,
            "node_id": self.node_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
            "event": self.event,
            "signature_algorithm": self.signature_algorithm,
            "hash_algorithm": self.hash_algorithm,
            "key_id": self.key_id,
        }
        if include_signature:
            data["signature"] = self.signature
        return data

    def to_json_line(self) -> str:
        """Serialise to a single JSONL line (canonical bytes, decoded as text)."""
        return canonical_bytes(self.to_dict()).decode("utf-8")

    # -- signing inputs ---------------------------------------------------

    def hash_payload(self) -> bytes:
        """Canonical bytes whose SHA3-256 digest is ``event_hash``.

        Excludes ``event_hash`` itself and ``signature``.
        """
        data = {k: v for k, v in self.to_dict().items() if k not in _HASH_EXCLUDED}
        return canonical_bytes(data)

    def signing_payload(self) -> bytes:
        """Canonical bytes covered by ``signature``.

        Excludes only ``signature``; ``event_hash`` *is* included, which is what
        binds the signature to the chain position.
        """
        data = {k: v for k, v in self.to_dict().items() if k not in _SIGNATURE_EXCLUDED}
        return canonical_bytes(data)

    def with_signature(self, signature_b64: str, signature_raw: bytes) -> SignedEvent:
        """Return a copy carrying the given signature."""
        return SignedEvent(
            format_version=self.format_version,
            node_id=self.node_id,
            sequence=self.sequence,
            timestamp=self.timestamp,
            previous_event_hash=self.previous_event_hash,
            event_hash=self.event_hash,
            event=self.event,
            signature_algorithm=self.signature_algorithm,
            hash_algorithm=self.hash_algorithm,
            key_id=self.key_id,
            signature=signature_b64,
            signature_bytes=signature_raw,
        )

    def with_event_hash(self, event_hash: str) -> SignedEvent:
        """Return a copy carrying the given ``event_hash``."""
        return SignedEvent(
            format_version=self.format_version,
            node_id=self.node_id,
            sequence=self.sequence,
            timestamp=self.timestamp,
            previous_event_hash=self.previous_event_hash,
            event_hash=event_hash,
            event=self.event,
            signature_algorithm=self.signature_algorithm,
            hash_algorithm=self.hash_algorithm,
            key_id=self.key_id,
            signature=self.signature,
            signature_bytes=self.signature_bytes,
        )

    # -- construction -----------------------------------------------------

    @staticmethod
    def build_unsigned(
        node_id: str,
        sequence: int,
        timestamp: str,
        previous_event_hash: str,
        event: dict[str, Any],
        key_id: str,
        signature_algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
        hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
        format_version: str = EVIDENCE_FORMAT_VERSION,
    ) -> SignedEvent:
        """Build a validated envelope with an empty ``event_hash`` and signature.

        The timestamp is normalised here, so the value that gets hashed is the
        value that gets stored.
        """
        _require(
            format_version in SUPPORTED_FORMAT_VERSIONS,
            f"unsupported format_version {format_version!r}",
            "unsupported_format_version",
        )
        _require(
            signature_algorithm in SUPPORTED_SIGNATURE_ALGORITHMS,
            f"unsupported signature_algorithm {signature_algorithm!r}",
            "unsupported_algorithm",
        )
        _require(
            hash_algorithm in SUPPORTED_HASH_ALGORITHMS,
            f"unsupported hash_algorithm {hash_algorithm!r}",
            "unsupported_algorithm",
        )
        try:
            normalized = normalize_timestamp(timestamp)
        except CanonicalizationError as exc:
            raise EvidenceValidationError(str(exc), "malformed_evidence") from exc

        return SignedEvent(
            format_version=format_version,
            node_id=_validate_identifier(node_id, "node_id"),
            sequence=_validate_sequence(sequence),
            timestamp=normalized,
            previous_event_hash=_validate_hash(previous_event_hash, "previous_event_hash"),
            event_hash="0" * 64,
            event=_validate_event(event),
            signature_algorithm=signature_algorithm,
            hash_algorithm=hash_algorithm,
            key_id=_validate_identifier(key_id, "key_id"),
            signature="",
            signature_bytes=b"",
        )


def parse_signed_event(
    data: Any, max_bytes: int = MAX_EVIDENCE_BYTES, require_signature: bool = True
) -> SignedEvent:
    """Validate an already-decoded evidence mapping into a :class:`SignedEvent`.

    Raises :class:`EvidenceValidationError` — never anything else — for any
    structural problem.
    """
    _require(isinstance(data, dict), "evidence record must be a JSON object")

    unknown = set(data) - set(ENVELOPE_FIELDS)
    _require(not unknown, f"unknown envelope field(s): {sorted(unknown)}")

    required = set(ENVELOPE_FIELDS)
    if not require_signature:
        required.discard("signature")
    missing = required - set(data)
    _require(not missing, f"missing envelope field(s): {sorted(missing)}")

    format_version = data["format_version"]
    _require(isinstance(format_version, str), "format_version must be a string")
    _require(
        format_version in SUPPORTED_FORMAT_VERSIONS,
        f"unsupported format_version {format_version!r}; "
        f"supported: {sorted(SUPPORTED_FORMAT_VERSIONS)}",
        "unsupported_format_version",
    )

    signature_algorithm = data["signature_algorithm"]
    _require(isinstance(signature_algorithm, str), "signature_algorithm must be a string")
    _require(
        signature_algorithm in SUPPORTED_SIGNATURE_ALGORITHMS,
        f"unsupported signature_algorithm {signature_algorithm!r}",
        "unsupported_algorithm",
    )

    hash_algorithm = data["hash_algorithm"]
    _require(isinstance(hash_algorithm, str), "hash_algorithm must be a string")
    _require(
        hash_algorithm in SUPPORTED_HASH_ALGORITHMS,
        f"unsupported hash_algorithm {hash_algorithm!r}",
        "unsupported_algorithm",
    )

    timestamp = data["timestamp"]
    try:
        normalized = normalize_timestamp(timestamp)
    except CanonicalizationError as exc:
        raise EvidenceValidationError(str(exc), "malformed_evidence") from exc
    # The stored timestamp must already be canonical; otherwise the bytes that
    # were signed differ from the bytes present in the record.
    _require(
        timestamp == normalized,
        f"timestamp {timestamp!r} is not in canonical form (expected {normalized!r})",
    )

    signature = data.get("signature", "")
    signature_bytes = _validate_signature(signature) if require_signature else b""

    event = parse_signed_event_size_guard(data, max_bytes)

    return SignedEvent(
        format_version=format_version,
        node_id=_validate_identifier(data["node_id"], "node_id"),
        sequence=_validate_sequence(data["sequence"]),
        timestamp=normalized,
        previous_event_hash=_validate_hash(data["previous_event_hash"], "previous_event_hash"),
        event_hash=_validate_hash(data["event_hash"], "event_hash"),
        event=event,
        signature_algorithm=signature_algorithm,
        hash_algorithm=hash_algorithm,
        key_id=_validate_identifier(data["key_id"], "key_id"),
        signature=signature if isinstance(signature, str) else "",
        signature_bytes=signature_bytes,
    )


def parse_signed_event_size_guard(data: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Validate the nested event and the total serialized size."""
    event = _validate_event(data["event"])
    try:
        encoded = canonical_bytes(data)
    except CanonicalizationError as exc:
        raise EvidenceValidationError(f"evidence is not canonicalizable: {exc}") from exc
    except UnicodeError as exc:  # pragma: no cover - belt and braces
        raise EvidenceValidationError(f"evidence contains unencodable text: {exc}") from exc
    _require(
        len(encoded) <= max_bytes,
        f"evidence record is {len(encoded)} bytes, exceeding the {max_bytes} byte limit",
        "oversized_evidence",
    )
    return event


def parse_signed_event_json(
    text: str | bytes, max_bytes: int = MAX_EVIDENCE_BYTES, require_signature: bool = True
) -> SignedEvent:
    """Parse and validate one JSON evidence record from text or bytes.

    Enforces the size limit *before* decoding, rejects duplicate JSON keys, and
    turns every decoding failure into :class:`EvidenceValidationError`.
    """
    if isinstance(text, bytes):
        raw = text
    elif isinstance(text, str):
        try:
            raw = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            # A str carrying lone surrogates — for example one produced by an
            # earlier lenient decode — has no UTF-8 form. Reject it here rather
            # than letting the built-in exception escape a verification path.
            raise EvidenceValidationError(
                f"evidence text is not encodable as UTF-8 ({exc.reason} at index {exc.start})"
            ) from exc
    else:  # pragma: no cover - defensive
        raise EvidenceValidationError("evidence must be text or bytes")

    _require(
        len(raw) <= max_bytes,
        f"evidence record is {len(raw)} bytes, exceeding the {max_bytes} byte limit",
        "oversized_evidence",
    )

    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceValidationError(f"evidence is not valid UTF-8: {exc}") from exc

    try:
        data = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys, parse_constant=_no_constants)
    except EvidenceValidationError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise EvidenceValidationError(f"evidence is not valid JSON: {exc}") from exc

    return parse_signed_event(data, max_bytes=max_bytes, require_signature=require_signature)


def _no_constants(name: str) -> Any:
    """Reject the JSON extensions ``NaN``, ``Infinity`` and ``-Infinity``."""
    raise EvidenceValidationError(f"evidence contains the non-JSON constant {name}")
