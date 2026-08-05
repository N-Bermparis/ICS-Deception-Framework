"""Per-record verification: signatures, hashes and key status."""

from __future__ import annotations

import base64
import json

import pytest

from ics_deception.pqc_evidence.event_chain import ChainPosition
from ics_deception.pqc_evidence.key_registry import KeyRegistry
from ics_deception.pqc_evidence.models import parse_signed_event_json
from ics_deception.pqc_evidence.verifier import ALERTS, EvidenceVerifier
from tests.pqc_evidence.conftest import KEY_ID, NODE_ID, tamper, tamper_event

pytestmark = pytest.mark.pqc


@pytest.fixture
def verifier(registry: KeyRegistry) -> EvidenceVerifier:
    return EvidenceVerifier(registry)


# -- happy path -------------------------------------------------------------


def test_a_genuine_record_verifies(verifier, signed_lines):
    result, event = verifier.verify_line(signed_lines[0])

    assert result.valid is True
    assert result.errors == []
    assert result.node_id == NODE_ID
    assert result.key_id == KEY_ID
    assert event is not None


def test_the_result_carries_the_documented_report_fields(verifier, signed_lines):
    payload = verifier.verify_line(signed_lines[0])[0].to_dict()

    for field in ("valid", "node_id", "sequence", "event_hash", "errors", "warnings",
                  "verified_at"):
        assert field in payload


def test_every_alert_name_is_in_the_published_vocabulary():
    for alert in ALERTS:
        assert alert.startswith("pqc_")


# -- tampering --------------------------------------------------------------


def test_a_one_character_event_change_is_detected(verifier, signed_lines):
    modified = tamper_event(signed_lines[2], username="Admin")

    result, _ = verifier.verify_line(modified)

    assert result.valid is False
    assert "pqc_event_hash_mismatch" in result.errors
    assert "pqc_invalid_signature" in result.errors


def test_a_modified_timestamp_is_detected(verifier, signed_lines):
    modified = tamper(signed_lines[0], timestamp="2030-01-01T00:00:00.000000Z")

    result, _ = verifier.verify_line(modified)

    assert result.valid is False
    assert "pqc_event_hash_mismatch" in result.errors


def test_a_modified_sequence_is_detected(verifier, signed_lines):
    modified = tamper(signed_lines[0], sequence=999)

    result, _ = verifier.verify_line(modified)

    assert result.valid is False
    assert "pqc_event_hash_mismatch" in result.errors


def test_a_modified_previous_hash_is_detected(verifier, signed_lines):
    modified = tamper(signed_lines[1], previous_event_hash="a" * 64)

    result, _ = verifier.verify_line(modified)

    assert result.valid is False
    assert "pqc_event_hash_mismatch" in result.errors


def test_a_substituted_event_hash_alone_is_detected(verifier, signed_lines):
    record = json.loads(signed_lines[0])
    # Recompute nothing: just claim a different hash.
    modified = tamper(signed_lines[0], event_hash="b" * 64)

    result, _ = verifier.verify_line(modified)

    assert "pqc_event_hash_mismatch" in result.errors
    assert record["event_hash"] != "b" * 64


def test_a_replaced_signature_is_detected(verifier, signed_lines):
    modified = tamper(signed_lines[0], signature=base64.b64encode(b"\x00" * 3309).decode())

    result, _ = verifier.verify_line(modified)

    assert result.valid is False
    assert "pqc_invalid_signature" in result.errors


def test_a_truncated_signature_is_detected(verifier, signed_lines):
    record = json.loads(signed_lines[0])
    raw = base64.b64decode(record["signature"])
    modified = tamper(signed_lines[0], signature=base64.b64encode(raw[:-10]).decode())

    result, _ = verifier.verify_line(modified)

    assert result.valid is False
    assert "pqc_invalid_signature" in result.errors


def test_a_single_flipped_signature_bit_is_detected(verifier, signed_lines):
    record = json.loads(signed_lines[0])
    raw = bytearray(base64.b64decode(record["signature"]))
    raw[0] ^= 0x01
    modified = tamper(signed_lines[0], signature=base64.b64encode(bytes(raw)).decode())

    result, _ = verifier.verify_line(modified)

    assert "pqc_invalid_signature" in result.errors


def test_invalid_base64_is_reported_as_malformed(verifier, signed_lines):
    modified = tamper(signed_lines[0], signature="not base64 !!")

    result, event = verifier.verify_line(modified)

    assert result.valid is False
    assert "pqc_malformed_evidence" in result.errors
    assert event is None


def test_a_signature_from_another_record_does_not_verify(verifier, signed_lines):
    other = json.loads(signed_lines[1])["signature"]
    modified = tamper(signed_lines[0], signature=other)

    result, _ = verifier.verify_line(modified)

    assert "pqc_invalid_signature" in result.errors


# -- key problems -----------------------------------------------------------


def test_a_wrong_public_key_fails_verification(signed_lines, other_keypair):
    wrong = KeyRegistry()
    wrong.register(KEY_ID, NODE_ID, other_keypair.public_bytes, activated_at="2000-01-01T00:00:00Z")

    result, _ = EvidenceVerifier(wrong).verify_line(signed_lines[0])

    assert result.valid is False
    assert "pqc_invalid_signature" in result.errors


def test_an_unknown_key_is_reported(signed_lines):
    empty = KeyRegistry()

    result, _ = EvidenceVerifier(empty).verify_line(signed_lines[0])

    assert "pqc_unknown_key" in result.errors
    assert "pqc_unknown_node" in result.errors


def test_a_known_node_with_an_unknown_key_reports_only_the_key(signed_lines, other_keypair):
    registry = KeyRegistry()
    registry.register("some-other-key", NODE_ID, other_keypair.public_bytes)

    result, _ = EvidenceVerifier(registry).verify_line(signed_lines[0])

    assert "pqc_unknown_key" in result.errors
    assert "pqc_unknown_node" not in result.errors


def test_a_revoked_key_is_reported(signed_lines, registry):
    registry.revoke(KEY_ID, "node seized")

    result, _ = EvidenceVerifier(registry).verify_line(signed_lines[0])

    assert result.valid is False
    assert "pqc_revoked_key" in result.errors


def test_a_disabled_key_is_reported(signed_lines, registry):
    registry.disable(KEY_ID)

    result, _ = EvidenceVerifier(registry).verify_line(signed_lines[0])

    assert "pqc_revoked_key" in result.errors


def test_an_expired_key_is_reported(signed_lines, signing_keypair):
    registry = KeyRegistry()
    registry.register(
        KEY_ID,
        NODE_ID,
        signing_keypair.public_bytes,
        activated_at="2000-01-01T00:00:00Z",
        expires_at="2001-01-01T00:00:00Z",
    )

    result, _ = EvidenceVerifier(registry).verify_line(signed_lines[0])

    assert "pqc_expired_key" in result.errors


def test_a_key_used_before_activation_is_reported(signed_lines, signing_keypair):
    registry = KeyRegistry()
    registry.register(
        KEY_ID, NODE_ID, signing_keypair.public_bytes, activated_at="2099-01-01T00:00:00Z"
    )

    result, _ = EvidenceVerifier(registry).verify_line(signed_lines[0])

    assert result.valid is False
    assert any("precedes key activation" in detail for detail in result.details)


def test_a_key_belonging_to_another_node_is_reported(signed_lines, signing_keypair):
    registry = KeyRegistry()
    registry.register(
        KEY_ID, "different-node", signing_keypair.public_bytes, activated_at="2000-01-01T00:00:00Z"
    )

    result, _ = EvidenceVerifier(registry).verify_line(signed_lines[0])

    assert "pqc_unknown_node" in result.errors


def test_an_algorithm_mismatch_is_reported(signed_lines, signing_keypair):
    registry = KeyRegistry()
    registry.register(
        KEY_ID,
        NODE_ID,
        signing_keypair.public_bytes,
        algorithm="ML-DSA-87",
        activated_at="2000-01-01T00:00:00Z",
    )

    result, _ = EvidenceVerifier(registry).verify_line(signed_lines[0])

    assert "pqc_unsupported_algorithm" in result.errors


# -- chain checks -----------------------------------------------------------


def test_chain_position_accepts_a_correct_genesis(verifier, signed_lines):
    event = parse_signed_event_json(signed_lines[0])
    position = ChainPosition(node_id=NODE_ID)

    result = verifier.verify_event(event, position)

    assert result.valid is True


def test_a_wrong_genesis_previous_hash_is_reported(verifier, signer):
    from ics_deception.pqc_evidence.event_chain import compute_event_hash
    from ics_deception.pqc_evidence.models import SignedEvent

    envelope = SignedEvent.build_unsigned(
        node_id=NODE_ID,
        sequence=1,
        timestamp="2026-08-05T18:15:00Z",
        previous_event_hash="e" * 64,  # not this node's derived genesis
        event={"source": "s", "event_type": "t"},
        key_id=KEY_ID,
    )
    envelope = envelope.with_event_hash(compute_event_hash(envelope))

    result = verifier.verify_event(envelope, ChainPosition(node_id=NODE_ID))

    assert "pqc_previous_hash_mismatch" in result.errors


def test_a_sequence_gap_is_reported(verifier, signed_lines):
    third = parse_signed_event_json(signed_lines[2])
    position = ChainPosition(node_id=NODE_ID)

    result = verifier.verify_event(third, position)

    assert "pqc_sequence_gap" in result.errors


def test_the_genesis_of_a_restarted_chain_is_reported_as_a_reset(verifier, signed_lines):
    first = parse_signed_event_json(signed_lines[0])
    position = ChainPosition(node_id=NODE_ID, last_sequence=5, last_event_hash="d" * 64)

    result = verifier.verify_event(first, position)

    assert "pqc_chain_reset" in result.errors


def test_verifying_never_raises_on_hostile_input(verifier):
    for hostile in ["", "{}", "null", "[]", "{" * 100, '{"a":1}', "\x00"]:
        result, event = verifier.verify_line(hostile)
        assert result.valid is False or event is None
