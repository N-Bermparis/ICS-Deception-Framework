"""Deterministic canonical JSON.

Hashing and signing must operate on bytes that are reproducible on any machine,
in any Python version, in any locale. Pretty-printed or dict-ordered JSON is
not: ``{"a":1,"b":2}`` and ``{"b": 2, "a": 1}`` are the same document but
different bytes, and signing the second would make the first fail verification.

Canonical form used here (a restricted, strictly-typed profile close to
RFC 8785 / JCS):

* UTF-8 encoded, no byte-order mark.
* Object keys sorted by Unicode code point.
* Compact separators — ``,`` and ``:`` with no spaces.
* No trailing newline.
* Non-ASCII characters emitted literally (``ensure_ascii=False``), so the
  encoding is genuinely UTF-8 rather than escaped ASCII.
* Integers emitted as-is; floats are **rejected**.

Deliberately rejected values, because each of them makes the bytes ambiguous or
platform-dependent:

* ``float`` (including whole-valued floats) — repr differs across
  implementations and ``1.0`` vs ``1`` is not a safe distinction to sign.
* ``NaN`` and ``±Infinity`` — not valid JSON at all.
* ``bool`` is allowed, but note ``True == 1`` in Python; the canonicalizer emits
  ``true``/``false`` and never coerces.
* ``bytes``, ``set``, ``datetime`` and any other non-JSON type.
* Non-string object keys.
* Strings containing lone surrogates.

What is hashed and signed
-------------------------
Two related byte strings are derived from one envelope:

``event_hash`` input
    The canonical form of the envelope **excluding** ``event_hash`` and
    ``signature``.
signature input
    The canonical form of the envelope **excluding** ``signature`` only, i.e.
    including the already-computed ``event_hash``.

So the signature covers every security-relevant field: ``format_version``,
``node_id``, ``sequence``, ``timestamp``, ``previous_event_hash``,
``event_hash``, the nested ``event``, ``signature_algorithm``,
``hash_algorithm`` and ``key_id``.
"""

from __future__ import annotations

import json
import math
from typing import Any

from ics_deception.pqc_evidence import EvidenceError

__all__ = [
    "CanonicalizationError",
    "canonical_bytes",
    "canonical_string",
    "check_canonicalizable",
    "normalize_timestamp",
]

#: Maximum nesting depth accepted inside a canonicalized document.
MAX_DEPTH = 32


class CanonicalizationError(EvidenceError):
    """A value cannot be represented in canonical JSON."""


#: Unicode surrogate range. ``json.loads`` happily turns the escape ``\ud800``
#: into a lone surrogate, which is a valid ``str`` but has **no** UTF-8
#: encoding. Encoding it later raises ``UnicodeEncodeError`` from deep inside
#: serialisation, so it is detected explicitly and up front instead.
_SURROGATE_LOW = 0xD800
_SURROGATE_HIGH = 0xDFFF

#: Maximum length of any single string value, to bound memory before encoding.
MAX_STRING_LENGTH = 1_000_000


def _check_string(value: str, path: str) -> None:
    """Validate that a string is encodable, bounded and free of surrogates."""
    if len(value) > MAX_STRING_LENGTH:
        raise CanonicalizationError(
            f"string at {path} is {len(value)} characters, "
            f"exceeding the {MAX_STRING_LENGTH} character limit"
        )
    for index, character in enumerate(value):
        if _SURROGATE_LOW <= ord(character) <= _SURROGATE_HIGH:
            # Deliberately does not echo the offending text back: the value is
            # attacker-controlled and the position is enough to diagnose it.
            raise CanonicalizationError(
                f"string at {path} contains an unpaired Unicode surrogate "
                f"(U+{ord(character):04X}) at index {index}; it has no UTF-8 encoding"
            )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - surrogates are the only cause
        raise CanonicalizationError(
            f"string at {path} is not encodable as UTF-8 ({exc.reason})"
        ) from exc


def _check(value: Any, depth: int, path: str) -> None:
    """Recursively validate that ``value`` is canonicalizable."""
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH} levels at {path}")

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        # Rejected even when finite: JSON float formatting is not stable enough
        # to sign. Callers should send integers or strings.
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(f"non-finite number at {path}")
        raise CanonicalizationError(
            f"float at {path}: use an integer or a string, floats are not canonicalizable"
        )
    if isinstance(value, str):
        _check_string(value, path)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"non-string object key {key!r} at {path} (type {type(key).__name__})"
                )
            _check_string(key, f"{path}.<key>")
            _check(item, depth + 1, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check(item, depth + 1, f"{path}[{index}]")
        return

    raise CanonicalizationError(
        f"unsupported type {type(value).__name__} at {path}; "
        "allowed: null, bool, int, str, list, dict"
    )


def check_canonicalizable(value: Any) -> None:
    """Raise :class:`CanonicalizationError` if ``value`` cannot be canonicalized."""
    _check(value, 0, "$")


def canonical_string(value: Any) -> str:
    """Return the canonical JSON text for ``value``."""
    check_canonicalizable(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:  # pragma: no cover - guarded by _check
        raise CanonicalizationError(f"value is not serialisable as canonical JSON: {exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes for ``value``.

    These are the exact bytes that get hashed and signed. The final encode is
    guarded so that no encoding failure can escape as a bare
    :class:`UnicodeEncodeError` from inside a signing or verification path.
    """
    text = canonical_string(value)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - _check_string catches these
        raise CanonicalizationError(
            f"canonical JSON is not encodable as UTF-8 ({exc.reason} at index {exc.start})"
        ) from exc


def normalize_timestamp(timestamp: str) -> str:
    """Normalise an ISO 8601 timestamp to a single canonical UTC spelling.

    ``2026-08-05T18:15:00+00:00``, ``2026-08-05T18:15:00Z`` and
    ``2026-08-05T20:15:00+02:00`` all denote the same instant but are different
    strings. Signing the raw string would make two semantically identical events
    produce different bytes, so every timestamp is normalised to UTC with
    microsecond precision and a trailing ``Z`` **before** hashing:

        ``YYYY-MM-DDTHH:MM:SS.ffffffZ``

    Raises :class:`CanonicalizationError` for unparseable input or for a
    timestamp with no timezone, since a naive timestamp is ambiguous.
    """
    from datetime import datetime, timezone

    if not isinstance(timestamp, str) or not timestamp:
        raise CanonicalizationError("timestamp must be a non-empty string")

    text = timestamp.strip()
    # datetime.fromisoformat only learned to parse a trailing "Z" in 3.11.
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise CanonicalizationError(f"unparseable ISO 8601 timestamp {timestamp!r}: {exc}") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CanonicalizationError(
            f"timestamp {timestamp!r} has no timezone; an explicit UTC offset is required"
        )

    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
