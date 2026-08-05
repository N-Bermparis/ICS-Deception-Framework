"""Strict validation of the signed-event envelope."""

from __future__ import annotations

import json

import pytest

from ics_deception.pqc_evidence.models import (
    ENVELOPE_FIELDS,
    MAX_EVENT_DEPTH,
    EvidenceValidationError,
    SignedEvent,
    parse_signed_event,
    parse_signed_event_json,
)

HASH = "a" * 64
GOOD = {
    "format_version": "1.0",
    "node_id": "rpi-honeypot-01",
    "sequence": 154,
    "timestamp": "2026-08-05T18:15:00.000000Z",
    "previous_event_hash": HASH,
    "event_hash": "b" * 64,
    "event": {"source": "modbus_honeypot", "event_type": "critical_register_write"},
    "signature_algorithm": "ML-DSA-65",
    "hash_algorithm": "SHA3-256",
    "key_id": "rpi-honeypot-01-2026-01",
    "signature": "QUJD",
}


def make(**overrides) -> dict:
    return {**GOOD, **overrides}


def as_json(data: dict) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


# -- happy path -------------------------------------------------------------


def test_a_well_formed_envelope_parses():
    event = parse_signed_event(GOOD)

    assert event.node_id == "rpi-honeypot-01"
    assert event.sequence == 154
    assert event.signature_bytes == b"ABC"


def test_round_trip_through_json_preserves_every_field():
    event = parse_signed_event_json(as_json(GOOD))
    again = parse_signed_event_json(event.to_json_line())

    assert again.to_dict() == event.to_dict()


def test_field_order_is_canonical():
    assert tuple(parse_signed_event(GOOD).to_dict()) == ENVELOPE_FIELDS


def test_hash_payload_excludes_event_hash_and_signature():
    payload = json.loads(parse_signed_event(GOOD).hash_payload())

    assert "event_hash" not in payload
    assert "signature" not in payload
    assert payload["node_id"] == "rpi-honeypot-01"


def test_signing_payload_covers_every_security_relevant_field():
    payload = json.loads(parse_signed_event(GOOD).signing_payload())

    assert "signature" not in payload
    for field in (
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
    ):
        assert field in payload, f"{field} is not covered by the signature"


# -- structural rejection ---------------------------------------------------


@pytest.mark.parametrize("field", ENVELOPE_FIELDS)
def test_every_required_field_is_required(field):
    data = make()
    del data[field]

    with pytest.raises(EvidenceValidationError, match="missing"):
        parse_signed_event(data)


def test_unknown_fields_are_rejected():
    with pytest.raises(EvidenceValidationError, match="unknown envelope field"):
        parse_signed_event(make(injected="unsigned data"))


def test_a_non_object_record_is_rejected():
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(["not", "an", "object"])


# -- field-level rejection --------------------------------------------------


@pytest.mark.parametrize("version", ["0.9", "2.0", "", "1", None, 1.0])
def test_unsupported_format_versions_are_rejected(version):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(format_version=version))


@pytest.mark.parametrize(
    "algorithm", ["RSA-4096", "Ed25519", "ECDSA-P256", "HMAC-SHA256", "", None]
)
def test_classical_signature_algorithms_are_rejected(algorithm):
    with pytest.raises(EvidenceValidationError) as excinfo:
        parse_signed_event(make(signature_algorithm=algorithm))
    assert excinfo.value.reason in ("unsupported_algorithm", "malformed_evidence")


@pytest.mark.parametrize("algorithm", ["SHA256", "MD5", "SHA3-512", ""])
def test_unsupported_hash_algorithms_are_rejected(algorithm):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(hash_algorithm=algorithm))


@pytest.mark.parametrize("sequence", [0, -1, "1", 1.0, True, None, 2**63])
def test_non_positive_or_non_integer_sequences_are_rejected(sequence):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(sequence=sequence))


@pytest.mark.parametrize(
    "node_id",
    ["", "a" * 129, "../escape", "node/with/slash", "node with space", "\x00", None, 42],
)
def test_invalid_node_identifiers_are_rejected(node_id):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(node_id=node_id))


@pytest.mark.parametrize("key_id", ["", "a" * 129, "key/../etc", None])
def test_invalid_key_identifiers_are_rejected(key_id):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(key_id=key_id))


@pytest.mark.parametrize(
    "value", ["", "z" * 64, "A" * 64, "a" * 63, "a" * 65, None, 12345]
)
def test_invalid_hashes_are_rejected(value):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(event_hash=value))
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(previous_event_hash=value))


def test_uppercase_hex_hashes_are_rejected():
    with pytest.raises(EvidenceValidationError, match="lowercase"):
        parse_signed_event(make(event_hash="A" * 64))


@pytest.mark.parametrize(
    "signature", ["", "not base64!!", "QUJ D", "====", None, 123, "QUJDZ"]
)
def test_invalid_base64_signatures_are_rejected(signature):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(signature=signature))


def test_a_non_canonical_timestamp_is_rejected():
    # Same instant, different spelling: the bytes signed would not match.
    with pytest.raises(EvidenceValidationError, match="canonical form"):
        parse_signed_event(make(timestamp="2026-08-05T20:15:00+02:00"))


def test_a_naive_timestamp_is_rejected():
    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(timestamp="2026-08-05T18:15:00"))


def test_a_non_object_event_is_rejected():
    with pytest.raises(EvidenceValidationError, match="event must be"):
        parse_signed_event(make(event="a string"))


# -- JSON-level rejection ---------------------------------------------------


def test_duplicate_json_keys_are_rejected():
    # A repeated key: json.loads would silently keep the last value, so a
    # naive reader and a verifier could disagree about what was signed.
    text = '{"format_version":"1.0",' + as_json(GOOD)[1:]

    with pytest.raises(EvidenceValidationError, match="duplicate JSON key"):
        parse_signed_event_json(text)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_json_non_finite_constants_are_rejected(constant):
    text = as_json(GOOD).replace('"sequence":154', f'"sequence":{constant}')

    with pytest.raises(EvidenceValidationError):
        parse_signed_event_json(text)


def test_malformed_json_is_rejected():
    with pytest.raises(EvidenceValidationError, match="not valid JSON"):
        parse_signed_event_json('{"format_version": "1.0"')


def test_invalid_utf8_is_rejected():
    with pytest.raises(EvidenceValidationError, match="not valid UTF-8"):
        parse_signed_event_json(b'{"a": "\xff\xfe"}')


def test_an_oversized_record_is_rejected_before_parsing():
    with pytest.raises(EvidenceValidationError) as excinfo:
        parse_signed_event_json(as_json(GOOD), max_bytes=10)
    assert excinfo.value.reason == "oversized_evidence"


def test_an_oversized_event_body_is_rejected():
    huge = make(event={"blob": "x" * 100_000})

    with pytest.raises(EvidenceValidationError) as excinfo:
        parse_signed_event(huge)
    assert excinfo.value.reason == "oversized_evidence"


def test_an_excessively_nested_event_is_rejected():
    nested: dict = {}
    cursor = nested
    for _ in range(MAX_EVENT_DEPTH + 3):
        cursor["n"] = {}
        cursor = cursor["n"]

    with pytest.raises(EvidenceValidationError):
        parse_signed_event(make(event=nested))


def test_parsing_hostile_input_never_raises_an_unexpected_exception():
    hostile = [
        "",
        "null",
        "[]",
        "0",
        '"string"',
        "{}",
        "{" * 200,
        '{"a":' * 50 + "1" + "}" * 50,
        "\x00\x01\x02",
        as_json(GOOD)[:-5],
    ]
    for text in hostile:
        with pytest.raises(EvidenceValidationError):
            parse_signed_event_json(text)


# -- construction -----------------------------------------------------------


def test_build_unsigned_normalizes_the_timestamp():
    event = SignedEvent.build_unsigned(
        node_id="node-1",
        sequence=1,
        timestamp="2026-08-05T20:15:00+02:00",
        previous_event_hash=HASH,
        event={"source": "s", "event_type": "t"},
        key_id="node-1-k1",
    )

    assert event.timestamp == "2026-08-05T18:15:00.000000Z"


def test_build_unsigned_rejects_an_unsupported_algorithm():
    with pytest.raises(EvidenceValidationError):
        SignedEvent.build_unsigned(
            node_id="node-1",
            sequence=1,
            timestamp="2026-08-05T18:15:00Z",
            previous_event_hash=HASH,
            event={},
            key_id="k",
            signature_algorithm="RSA-4096",
        )
