"""SHA3-256 chain construction, genesis behaviour and hash sensitivity."""

from __future__ import annotations

import hashlib

import pytest

from ics_deception.pqc_evidence.event_chain import (
    FIRST_SEQUENCE,
    GENESIS_DOMAIN,
    ChainPosition,
    compute_event_hash,
    expected_previous_hash,
    genesis_previous_hash,
    is_genesis,
    verify_event_hash,
)
from ics_deception.pqc_evidence.models import SignedEvent

NODE = "rpi-honeypot-01"


def build(sequence: int, previous: str, event: dict | None = None) -> SignedEvent:
    envelope = SignedEvent.build_unsigned(
        node_id=NODE,
        sequence=sequence,
        timestamp="2026-08-05T18:15:00Z",
        previous_event_hash=previous,
        event=event if event is not None else {"source": "s", "event_type": "t"},
        key_id="k1",
    )
    return envelope.with_event_hash(compute_event_hash(envelope))


# -- genesis ----------------------------------------------------------------


def test_genesis_hash_is_deterministic():
    assert genesis_previous_hash(NODE) == genesis_previous_hash(NODE)


def test_genesis_hash_is_node_bound():
    assert genesis_previous_hash("node-a") != genesis_previous_hash("node-b")


def test_genesis_hash_is_not_null_empty_or_zero():
    value = genesis_previous_hash(NODE)

    assert value not in ("", "0" * 64, None)
    assert len(value) == 64


def test_genesis_hash_matches_its_documented_derivation():
    expected = hashlib.sha3_256(GENESIS_DOMAIN + NODE.encode("utf-8")).hexdigest()

    assert genesis_previous_hash(NODE) == expected


def test_first_sequence_is_one():
    assert FIRST_SEQUENCE == 1
    assert is_genesis(build(1, genesis_previous_hash(NODE)))
    assert not is_genesis(build(2, "a" * 64))


def test_expected_previous_hash_at_genesis_ignores_the_cursor():
    assert expected_previous_hash(NODE, 1, None) == genesis_previous_hash(NODE)


def test_expected_previous_hash_requires_a_predecessor_after_genesis():
    with pytest.raises(ValueError, match="requires a previous event hash"):
        expected_previous_hash(NODE, 2, None)


# -- hashing ----------------------------------------------------------------


def test_event_hash_is_sha3_256_of_the_hash_payload():
    event = build(1, genesis_previous_hash(NODE))
    expected = hashlib.sha3_256(event.hash_payload()).hexdigest()

    assert event.event_hash == expected
    assert verify_event_hash(event)


def test_event_hash_is_independent_of_the_stored_event_hash():
    event = build(1, genesis_previous_hash(NODE))
    relabelled = event.with_event_hash("f" * 64)

    assert compute_event_hash(relabelled) == event.event_hash


def test_event_hash_is_independent_of_the_signature():
    event = build(1, genesis_previous_hash(NODE))
    signed = event.with_signature("QUJD", b"ABC")

    assert compute_event_hash(signed) == event.event_hash


@pytest.mark.parametrize(
    "changes",
    [
        {"sequence": 2},
        {"timestamp": "2026-08-05T18:15:01Z"},
        {"previous_event_hash": "c" * 64},
        {"event": {"source": "s", "event_type": "changed"}},
        {"key_id": "k2"},
        {"node_id": "other-node"},
    ],
)
def test_any_field_change_changes_the_event_hash(changes):
    base = SignedEvent.build_unsigned(
        node_id=NODE,
        sequence=1,
        timestamp="2026-08-05T18:15:00Z",
        previous_event_hash=genesis_previous_hash(NODE),
        event={"source": "s", "event_type": "t"},
        key_id="k1",
    )
    modified = SignedEvent.build_unsigned(
        node_id=changes.get("node_id", NODE),
        sequence=changes.get("sequence", 1),
        timestamp=changes.get("timestamp", "2026-08-05T18:15:00Z"),
        previous_event_hash=changes.get("previous_event_hash", genesis_previous_hash(NODE)),
        event=changes.get("event", {"source": "s", "event_type": "t"}),
        key_id=changes.get("key_id", "k1"),
    )

    assert compute_event_hash(base) != compute_event_hash(modified)


def test_a_one_character_event_change_changes_the_hash():
    first = build(1, genesis_previous_hash(NODE), {"source": "s", "event_type": "admin"})
    second = build(1, genesis_previous_hash(NODE), {"source": "s", "event_type": "Admin"})

    assert first.event_hash != second.event_hash


def test_verify_event_hash_detects_a_substituted_hash():
    event = build(1, genesis_previous_hash(NODE))

    assert not verify_event_hash(event.with_event_hash("0" * 64))


# -- chain position ---------------------------------------------------------


def test_a_fresh_cursor_starts_at_genesis():
    position = ChainPosition(node_id=NODE)

    assert position.next_sequence == 1
    assert position.previous_hash_for_next() == genesis_previous_hash(NODE)


def test_advancing_links_the_next_event():
    position = ChainPosition(node_id=NODE)
    first = build(1, position.previous_hash_for_next())
    position.advance(first)

    assert position.next_sequence == 2
    assert position.previous_hash_for_next() == first.event_hash


def test_a_three_event_chain_links_correctly():
    position = ChainPosition(node_id=NODE)
    chain = []
    for _ in range(3):
        event = build(position.next_sequence, position.previous_hash_for_next())
        chain.append(event)
        position.advance(event)

    assert [e.sequence for e in chain] == [1, 2, 3]
    assert chain[0].previous_event_hash == genesis_previous_hash(NODE)
    assert chain[1].previous_event_hash == chain[0].event_hash
    assert chain[2].previous_event_hash == chain[1].event_hash


def test_advance_can_override_the_hash_with_a_recomputed_value():
    position = ChainPosition(node_id=NODE)
    event = build(1, position.previous_hash_for_next())
    forged = event.with_event_hash("9" * 64)

    position.advance(forged, event_hash=compute_event_hash(forged))

    # The cursor follows reality, not the forger's claim.
    assert position.last_event_hash != "9" * 64
    assert position.last_event_hash == event.event_hash
