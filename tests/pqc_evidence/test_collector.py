"""Stream-level detection: deletion, reordering, duplication, replay and resets."""

from __future__ import annotations

import json

import pytest

from ics_deception.pqc_evidence.collector import CollectorError, EvidenceCollector
from ics_deception.pqc_evidence.key_registry import KeyRegistry
from ics_deception.pqc_evidence.signer import EvidenceSigner
from tests.pqc_evidence.conftest import KEY_ID, NODE_ID, tamper, tamper_event

pytestmark = pytest.mark.pqc


@pytest.fixture
def collector(registry: KeyRegistry) -> EvidenceCollector:
    return EvidenceCollector(registry)


# -- clean streams ----------------------------------------------------------


def test_a_clean_chain_verifies(collector, signed_lines):
    report = collector.verify_stream(signed_lines)

    assert report.valid is True
    assert report.verified == len(signed_lines)
    assert report.failed == 0
    assert report.alert_counts == {}


def test_the_report_summarises_each_node(collector, signed_lines):
    report = collector.verify_stream(signed_lines)

    assert set(report.nodes) == {NODE_ID}
    assert report.nodes[NODE_ID]["last_sequence"] == 5
    assert report.nodes[NODE_ID]["events"] == 5


def test_an_empty_stream_is_valid(collector):
    report = collector.verify_stream([])

    assert report.valid is True
    assert report.total == 0


def test_blank_lines_are_ignored(collector, signed_lines):
    report = collector.verify_stream(["", "   ", *signed_lines, "\n"])

    assert report.valid is True
    assert report.total == len(signed_lines)


def test_an_empty_file_is_valid(collector, tmp_path):
    path = tmp_path / "evidence.jsonl"
    path.write_text("", encoding="utf-8")

    report = collector.verify_file(path)

    assert report.valid is True
    assert report.total == 0


def test_a_missing_file_raises(collector, tmp_path):
    with pytest.raises(CollectorError, match="not found"):
        collector.verify_file(tmp_path / "absent.jsonl")


def test_a_file_without_a_trailing_newline_verifies(collector, signed_lines, tmp_path):
    path = tmp_path / "evidence.jsonl"
    path.write_text("\n".join(signed_lines), encoding="utf-8")

    assert collector.verify_file(path).valid is True


# -- chain attacks ----------------------------------------------------------


def test_a_deleted_event_is_detected(collector, signed_lines):
    report = collector.verify_stream(signed_lines[:2] + signed_lines[3:])

    assert report.valid is False
    assert "pqc_sequence_gap" in report.alert_counts


def test_reordered_events_are_detected(collector, signed_lines):
    reordered = [signed_lines[0], signed_lines[2], signed_lines[1], *signed_lines[3:]]

    report = collector.verify_stream(reordered)

    assert report.valid is False
    assert "pqc_sequence_gap" in report.alert_counts or (
        "pqc_previous_hash_mismatch" in report.alert_counts
    )


def test_a_duplicated_event_is_detected_as_a_replay(collector, signed_lines):
    report = collector.verify_stream([*signed_lines, signed_lines[2]])

    assert report.valid is False
    assert "pqc_replayed_event" in report.alert_counts


def test_two_different_events_at_one_sequence_are_a_fork(
    collector, tmp_path, signing_keypair, pqc_backend, sample_events
):
    first = EvidenceSigner(
        NODE_ID, KEY_ID, signing_keypair.private_bytes, tmp_path / "a.json", backend=pqc_backend
    ).sign_event(sample_events[0])
    second = EvidenceSigner(
        NODE_ID, KEY_ID, signing_keypair.private_bytes, tmp_path / "b.json", backend=pqc_backend
    ).sign_event({"source": "forged", "event_type": "different"})

    report = collector.verify_stream([first.to_json_line(), second.to_json_line()])

    assert report.valid is False
    assert "pqc_duplicate_sequence" in report.alert_counts


def test_a_chain_reset_is_detected(
    collector, signed_lines, tmp_path, signing_keypair, pqc_backend
):
    restarted = EvidenceSigner(
        NODE_ID, KEY_ID, signing_keypair.private_bytes, tmp_path / "new.json", backend=pqc_backend
    ).sign_event({"source": "s", "event_type": "after-reset"})

    report = collector.verify_stream([*signed_lines, restarted.to_json_line()])

    assert report.valid is False
    assert "pqc_chain_reset" in report.alert_counts


def test_tampering_does_not_cascade_into_false_sequence_gaps(collector, signed_lines):
    modified = tamper_event(signed_lines[2], username="Admin")
    stream = [*signed_lines[:2], modified, *signed_lines[3:]]

    report = collector.verify_stream(stream)

    assert "pqc_event_hash_mismatch" in report.alert_counts
    # The records after the tampered one keep their correct sequence numbers,
    # so no spurious gap is reported.
    assert "pqc_sequence_gap" not in report.alert_counts
    assert report.failed == 2  # the tampered record and the one that linked to it


def test_a_forger_cannot_steer_the_chain_with_a_claimed_hash(collector, signed_lines):
    forged = tamper(signed_lines[1], event_hash="f" * 64)

    report = collector.verify_stream([signed_lines[0], forged, signed_lines[2]])

    assert "pqc_event_hash_mismatch" in report.alert_counts
    # Record 3 still links to the real hash of record 2, so it stays verifiable.
    assert report.verified >= 1


# -- malformed input --------------------------------------------------------


def test_a_corrupted_line_is_counted_without_stopping_the_run(collector, signed_lines):
    stream = [signed_lines[0], "{ this is not json", *signed_lines[1:]]

    report = collector.verify_stream(stream)

    assert report.malformed == 1
    assert "pqc_malformed_evidence" in report.alert_counts
    assert report.total == len(signed_lines) + 1


def test_a_partial_final_line_is_reported_as_malformed(collector, signed_lines):
    stream = [*signed_lines, signed_lines[0][: len(signed_lines[0]) // 2]]

    report = collector.verify_stream(stream)

    assert report.malformed == 1
    assert report.valid is False


def test_an_oversized_record_is_reported(registry, signed_lines):
    from ics_deception.pqc_evidence.models import EvidenceValidationError, parse_signed_event_json

    with pytest.raises(EvidenceValidationError) as excinfo:
        parse_signed_event_json(signed_lines[0], max_bytes=100)
    assert excinfo.value.reason == "oversized_evidence"


def test_duplicate_json_keys_are_reported_as_malformed(collector, signed_lines):
    injected = '{"sequence":99,' + signed_lines[0][1:]

    report = collector.verify_stream([injected])

    assert report.malformed == 1


def test_hostile_lines_never_crash_the_collector(collector):
    hostile = ["", "null", "[]", "{}", "0", '"x"', "{" * 500, "\x00\x01", "�"]

    report = collector.verify_stream(hostile)

    assert report.total == len([line for line in hostile if line.strip()])
    assert report.valid is False


# -- multiple nodes ---------------------------------------------------------


def test_two_nodes_are_tracked_independently(
    tmp_path, pqc_backend, signing_keypair, other_keypair, sample_events
):
    registry = KeyRegistry()
    registry.register("k-a", "node-a", signing_keypair.public_bytes,
                      activated_at="2000-01-01T00:00:00Z")
    registry.register("k-b", "node-b", other_keypair.public_bytes,
                      activated_at="2000-01-01T00:00:00Z")

    signer_a = EvidenceSigner(
        "node-a", "k-a", signing_keypair.private_bytes, tmp_path / "a.json", backend=pqc_backend
    )
    signer_b = EvidenceSigner(
        "node-b", "k-b", other_keypair.private_bytes, tmp_path / "b.json", backend=pqc_backend
    )

    interleaved = []
    for event in sample_events[:3]:
        interleaved.append(signer_a.sign_event(event).to_json_line())
        interleaved.append(signer_b.sign_event(event).to_json_line())

    report = EvidenceCollector(registry).verify_stream(interleaved)

    assert report.valid is True
    assert report.nodes["node-a"]["last_sequence"] == 3
    assert report.nodes["node-b"]["last_sequence"] == 3


# -- iteration and limits ---------------------------------------------------


def test_iter_valid_events_yields_only_sound_records(collector, signed_lines):
    stream = [signed_lines[0], "garbage", tamper_event(signed_lines[1], x=1), signed_lines[2]]

    valid = list(collector.iter_valid_events(stream))

    assert [event.sequence for event in valid] == [1, 3]


def test_results_are_capped_to_bound_memory(registry, signed_lines):
    collector = EvidenceCollector(registry, max_results=2)

    report = collector.verify_stream(signed_lines)

    assert len(report.results) == 2
    assert report.truncated_results is True


def test_verify_one_checks_a_single_record(collector, signed_lines):
    assert collector.verify_one(signed_lines[0]).valid is True
    assert collector.verify_one("nonsense").valid is False


def test_the_report_serialises_to_json(collector, signed_lines):
    payload = collector.verify_stream(signed_lines).to_dict()

    json.dumps(payload)  # must not raise
    assert payload["valid"] is True
    assert payload["verified"] == 5
