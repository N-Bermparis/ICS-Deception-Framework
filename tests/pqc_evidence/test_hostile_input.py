"""Hostile Unicode, malformed JSON and record-size limits.

Every one of these inputs must produce a **structured** framework exception, not
a bare built-in one escaping from a parsing or canonicalization path. A verifier
that crashes on hostile input is a denial-of-service in the tool meant to
analyse an attack.
"""

from __future__ import annotations

import json

import pytest

from ics_deception.pqc_evidence.canonicalizer import (
    MAX_STRING_LENGTH,
    CanonicalizationError,
    canonical_bytes,
)
from ics_deception.pqc_evidence.collector import CollectorError, EvidenceCollector
from ics_deception.pqc_evidence.key_registry import KeyRegistry
from ics_deception.pqc_evidence.models import (
    MAX_EVIDENCE_BYTES,
    EvidenceValidationError,
    parse_signed_event,
    parse_signed_event_json,
)
from ics_deception.pqc_evidence.verifier import (
    MAX_EVIDENCE_BYTES_CEILING,
    EvidenceVerifier,
    VerifierError,
)

HASH = "a" * 64
GOOD = {
    "format_version": "1.0",
    "node_id": "rpi-honeypot-01",
    "sequence": 1,
    "timestamp": "2026-08-05T18:15:00.000000Z",
    "previous_event_hash": HASH,
    "event_hash": "b" * 64,
    "event": {"source": "modbus_honeypot", "event_type": "probe"},
    "signature_algorithm": "ML-DSA-65",
    "hash_algorithm": "SHA3-256",
    "key_id": "rpi-honeypot-01-2026-01",
    "signature": "QUJD",
}


def envelope(**overrides) -> str:
    return json.dumps({**GOOD, **overrides}, separators=(",", ":"), sort_keys=True)


# ===========================================================================
# Unicode
# ===========================================================================


def test_a_lone_surrogate_in_an_event_is_a_structured_failure():
    """``json.loads`` accepts \\ud800; it has no UTF-8 encoding.

    Encoding it later raised a bare ``UnicodeEncodeError`` out of the signing
    path. It must be caught and reported as evidence validation instead.
    """
    hostile = envelope(event={"source": "s", "event_type": "t", "x": "\ud800"})

    with pytest.raises(EvidenceValidationError) as excinfo:
        parse_signed_event_json(hostile)

    assert "surrogate" in str(excinfo.value).lower()


@pytest.mark.parametrize(
    "text",
    ['{"x":"\\ud800"}', '{"x":"\\udfff"}', '{"x":"a\\ud800b"}', '{"\\ud800":"key"}'],
)
def test_surrogates_anywhere_are_rejected_by_the_canonicalizer(text):
    value = json.loads(text)

    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


def test_a_surrogate_in_an_object_key_is_rejected():
    with pytest.raises(CanonicalizationError, match="surrogate"):
        canonical_bytes({"\ud800": 1})


def test_a_surrogate_in_a_nested_list_is_rejected():
    with pytest.raises(CanonicalizationError, match="surrogate"):
        canonical_bytes({"a": [{"b": ["\udfff"]}]})


def test_the_error_message_does_not_echo_the_hostile_text():
    """Error text lands in logs and dashboards; it must not carry raw payload."""
    marker = "SECRET-ATTACKER-MARKER"
    hostile = envelope(node_id=f"{marker}/../../etc")

    with pytest.raises(EvidenceValidationError) as excinfo:
        parse_signed_event_json(hostile)

    message = str(excinfo.value)
    assert len(message) < 300
    assert "\\" in message or marker[:16] in message  # bounded excerpt only
    assert "../../etc" not in message


def test_invalid_utf8_bytes_are_rejected():
    with pytest.raises(EvidenceValidationError, match="not valid UTF-8"):
        parse_signed_event_json(b'{"a": "\xff\xfe"}')


def test_a_surrogate_bearing_str_is_rejected_before_parsing():
    with pytest.raises(EvidenceValidationError, match="not encodable"):
        parse_signed_event_json('{"a": "\ud800"}')


def test_an_overlong_string_is_rejected():
    with pytest.raises(CanonicalizationError, match="character limit"):
        canonical_bytes({"a": "x" * (MAX_STRING_LENGTH + 1)})


# ===========================================================================
# Hostile JSON
# ===========================================================================


def test_duplicate_json_keys_are_rejected():
    text = '{"format_version":"1.0",' + envelope()[1:]

    with pytest.raises(EvidenceValidationError, match="duplicate JSON key"):
        parse_signed_event_json(text)


def test_a_duplicate_key_inside_the_event_is_rejected():
    text = envelope().replace('"event":{', '"event":{"source":"a","source":"b",', 1)

    with pytest.raises(EvidenceValidationError, match="duplicate JSON key"):
        parse_signed_event_json(text)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_constants_are_rejected(constant):
    text = envelope().replace('"sequence":1', f'"sequence":{constant}')

    with pytest.raises(EvidenceValidationError):
        parse_signed_event_json(text)


def test_a_non_finite_constant_inside_the_event_is_rejected():
    text = envelope().replace('"event_type":"probe"', '"event_type":"probe","v":NaN')

    with pytest.raises(EvidenceValidationError):
        parse_signed_event_json(text)


def test_excessive_nesting_is_rejected():
    nested: dict = {}
    cursor = nested
    for _ in range(200):
        cursor["n"] = {}
        cursor = cursor["n"]

    with pytest.raises(EvidenceValidationError):
        parse_signed_event({**GOOD, "event": nested})


def test_deeply_nested_raw_json_does_not_crash_the_parser():
    text = '{"a":' * 2000 + "1" + "}" * 2000

    with pytest.raises(EvidenceValidationError):
        parse_signed_event_json(text)


@pytest.mark.parametrize(
    "signature", ["", "not base64!!", "QUJ D", "====", "QUJDZ", "AA==AA=="]
)
def test_invalid_base64_is_rejected_strictly(signature):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event_json(envelope(signature=signature))


@pytest.mark.parametrize(
    "value", ["", "z" * 64, "A" * 64, "a" * 63, "a" * 65, "0x" + "a" * 62]
)
def test_malformed_sha3_hashes_are_rejected(value):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event_json(envelope(event_hash=value))


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-05T18:15:00",
        "2026-08-05 18:15:00Z",
        "2026-08-05T18:15:00+02:00",
        "not a timestamp",
        "",
        "2026-13-45T99:99:99Z",
    ],
)
def test_incorrect_timestamp_encodings_are_rejected(timestamp):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event_json(envelope(timestamp=timestamp))


@pytest.mark.parametrize("sequence", [1.5, "1", True, None, [], {}])
def test_unsupported_numeric_types_are_rejected(sequence):
    with pytest.raises(EvidenceValidationError):
        parse_signed_event({**GOOD, "sequence": sequence})


def test_a_float_inside_the_event_is_rejected():
    with pytest.raises(EvidenceValidationError):
        parse_signed_event({**GOOD, "event": {"source": "s", "event_type": "t", "v": 1.5}})


def test_hostile_input_never_raises_an_unexpected_exception():
    hostile = [
        "",
        "null",
        "[]",
        "0",
        '"string"',
        "{}",
        "{" * 500,
        "\x00\x01\x02",
        envelope()[:-5],
        b"\xff\xfe\xfd",
        '{"a":' * 100 + "1" + "}" * 100,
    ]
    for text in hostile:
        with pytest.raises(EvidenceValidationError):
            parse_signed_event_json(text)


# ===========================================================================
# Record-size limits are actually enforced
# ===========================================================================


def test_changing_max_record_bytes_changes_behaviour():
    """The limit must reach the parser, not merely be stored on the collector."""
    registry = KeyRegistry()
    line = envelope()
    size = len(line)

    generous = EvidenceCollector(registry, max_record_bytes=size + 10)
    strict = EvidenceCollector(registry, max_record_bytes=size - 10)

    generous_report = generous.verify_stream([line])
    strict_report = strict.verify_stream([line])

    # The generous collector parses it (and fails on the unknown key, not size).
    assert "pqc_oversized_evidence" not in generous_report.alert_counts
    # The strict collector rejects it on size alone.
    assert "pqc_oversized_evidence" in strict_report.alert_counts
    assert strict_report.malformed == 1


def test_the_limit_is_enforced_on_a_single_record():
    registry = KeyRegistry()
    collector = EvidenceCollector(registry, max_record_bytes=50)

    result = collector.verify_one(envelope())

    assert result.valid is False
    assert "pqc_oversized_evidence" in result.errors


def test_the_verifier_enforces_its_own_limit():
    verifier = EvidenceVerifier(KeyRegistry(), max_record_bytes=50)

    result, event = verifier.verify_line(envelope())

    assert event is None
    assert "pqc_oversized_evidence" in result.errors


def test_an_oversized_line_is_rejected_without_parsing():
    """A hostile 10 MB line costs one length check, not a full JSON parse."""
    registry = KeyRegistry()
    collector = EvidenceCollector(registry, max_record_bytes=1024)
    monster = '{"a":"' + "x" * (10 * 1024 * 1024) + '"}'

    report = collector.verify_stream([monster])

    assert report.malformed == 1
    assert "pqc_oversized_evidence" in report.alert_counts


def test_the_default_limit_still_accepts_a_real_record(signed_lines):
    registry = KeyRegistry()
    collector = EvidenceCollector(registry, max_record_bytes=MAX_EVIDENCE_BYTES)

    report = collector.verify_stream(signed_lines[:1])

    assert "pqc_oversized_evidence" not in report.alert_counts


@pytest.mark.parametrize("limit", [0, -1, -1000])
def test_non_positive_limits_are_rejected(limit):
    with pytest.raises(CollectorError, match="greater than zero"):
        EvidenceCollector(KeyRegistry(), max_record_bytes=limit)
    with pytest.raises(VerifierError, match="greater than zero"):
        EvidenceVerifier(KeyRegistry(), max_record_bytes=limit)


def test_an_absurd_limit_is_rejected():
    with pytest.raises(VerifierError, match="must not exceed"):
        EvidenceVerifier(KeyRegistry(), max_record_bytes=MAX_EVIDENCE_BYTES_CEILING + 1)


def test_a_non_positive_max_results_is_rejected():
    with pytest.raises(CollectorError, match="greater than zero"):
        EvidenceCollector(KeyRegistry(), max_results=0)


def test_a_collector_pushes_its_limit_into_a_supplied_verifier():
    verifier = EvidenceVerifier(KeyRegistry())
    collector = EvidenceCollector(KeyRegistry(), verifier=verifier, max_record_bytes=99)

    assert collector.verifier.max_record_bytes == 99
