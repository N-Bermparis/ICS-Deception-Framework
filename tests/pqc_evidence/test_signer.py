"""Signing with real ML-DSA-65, including key handling and batch signing."""

from __future__ import annotations

import json
import os
import stat

import pytest

from ics_deception.pqc_evidence.crypto_backend import (
    TEST_BACKEND,
    TEST_KEY_MARKER,
    BackendUnavailableError,
    get_backend,
    select_backend,
)
from ics_deception.pqc_evidence.event_chain import compute_event_hash, genesis_previous_hash
from ics_deception.pqc_evidence.models import parse_signed_event_json
from ics_deception.pqc_evidence.signer import (
    EvidenceSigner,
    SignerError,
    load_private_key,
    write_private_key,
)
from tests.pqc_evidence.conftest import KEY_ID, NODE_ID

pytestmark = pytest.mark.pqc


# -- basic signing ----------------------------------------------------------


def test_signing_persists_the_record_immediately(signer, evidence_path):
    """sign_event returns only after the record is durably on disk."""
    record = signer.sign_event({"source": "s", "event_type": "t"})

    lines = evidence_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_hash"] == record.event_hash


def test_signing_produces_a_valid_genesis_record(signer, pqc_backend, signing_keypair):
    record = signer.sign_event({"source": "modbus_honeypot", "event_type": "probe"})

    assert record.sequence == 1
    assert record.previous_event_hash == genesis_previous_hash(NODE_ID)
    assert record.event_hash == compute_event_hash(record)
    assert record.signature_algorithm == "ML-DSA-65"
    assert record.hash_algorithm == "SHA3-256"
    assert record.node_id == NODE_ID
    assert record.key_id == KEY_ID
    assert pqc_backend.verify(
        signing_keypair.public_bytes, record.signing_payload(), record.signature_bytes, "ML-DSA-65"
    )


def test_ml_dsa_65_signature_has_the_fips_204_size(signer):
    record = signer.sign_event({"source": "s", "event_type": "t"})

    assert len(record.signature_bytes) == 3309


def test_sequences_increase_by_exactly_one(signer):
    records = [signer.sign_event({"source": "s", "event_type": "t", "n": n}) for n in range(5)]

    assert [r.sequence for r in records] == [1, 2, 3, 4, 5]


def test_each_record_links_to_its_predecessor(signer):
    records = [signer.sign_event({"source": "s", "event_type": "t", "n": n}) for n in range(4)]

    for previous, current in zip(records, records[1:], strict=False):
        assert current.previous_event_hash == previous.event_hash


def test_the_signed_line_round_trips_through_the_parser(signer):
    record = signer.sign_event({"source": "s", "event_type": "t"})

    reparsed = parse_signed_event_json(record.to_json_line())

    assert reparsed.event_hash == record.event_hash
    assert reparsed.signature_bytes == record.signature_bytes


def test_state_is_committed_so_a_restart_continues_the_chain(
    tmp_path, signing_keypair, pqc_backend
):
    state = tmp_path / "state.json"
    evidence = tmp_path / "evidence.jsonl"

    first = EvidenceSigner(
        NODE_ID, KEY_ID, signing_keypair.private_bytes, state, evidence, backend=pqc_backend
    )
    first.sign_event({"source": "s", "event_type": "t"})
    first.sign_event({"source": "s", "event_type": "t"})

    resumed = EvidenceSigner(
        NODE_ID, KEY_ID, signing_keypair.private_bytes, state, evidence, backend=pqc_backend
    )
    third = resumed.sign_event({"source": "s", "event_type": "t"})

    assert third.sequence == 3


def test_an_explicit_timestamp_is_normalized(signer):
    record = signer.sign_event(
        {"source": "s", "event_type": "t"}, timestamp="2026-08-05T20:15:00+02:00"
    )

    assert record.timestamp == "2026-08-05T18:15:00.000000Z"


def test_signing_rejects_a_non_canonicalizable_event(signer):
    from ics_deception.pqc_evidence.models import EvidenceValidationError

    with pytest.raises(EvidenceValidationError):
        signer.sign_event({"source": "s", "event_type": "t", "bad": 1.5})


# -- batch and log signing --------------------------------------------------


def test_sign_events_assigns_contiguous_sequences(signer):
    events = ({"source": "s", "event_type": "t", "n": n} for n in range(10))

    records = list(signer.sign_events(events))

    assert [r.sequence for r in records] == list(range(1, 11))


def test_sign_log_writes_one_record_per_input_line(signer, evidence_path):
    source = [json.dumps({"source": "s", "event_type": "t", "n": n}) for n in range(3)]

    report = signer.sign_log(source)

    assert report.signed == 3
    assert report.first_sequence == 1
    assert report.last_sequence == 3
    assert len(evidence_path.read_text(encoding="utf-8").strip().splitlines()) == 3


def test_sign_log_skips_blank_lines_and_counts_bad_ones(signer):
    source = ['{"source":"s","event_type":"t"}', "", "   ", "not json", "[1,2]"]

    report = signer.sign_log(source)

    assert report.signed == 1
    assert report.skipped == 2
    assert report.errors == 2


def test_sign_log_honours_max_events(signer):
    source = [json.dumps({"source": "s", "event_type": "t", "n": n}) for n in range(10)]

    report = signer.sign_log(source, max_events=4)

    assert report.signed == 4


def test_sign_log_reports_the_backend_and_whether_it_is_real(signer):
    report = signer.sign_log(['{"source":"s","event_type":"t"}'])

    assert report.backend in ("openssl", "pyfips")
    assert report.real_pqc is True


# -- key files --------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_written_private_keys_are_owner_only(tmp_path, signing_keypair):
    path = write_private_key(tmp_path / "node.key", signing_keypair)

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {mode:04o}"


def test_write_private_key_refuses_to_clobber(tmp_path, signing_keypair):
    path = tmp_path / "node.key"
    write_private_key(path, signing_keypair)

    with pytest.raises(SignerError, match="refusing to overwrite"):
        write_private_key(path, signing_keypair)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_loading_a_world_readable_private_key_is_refused(tmp_path, signing_keypair):
    path = write_private_key(tmp_path / "node.key", signing_keypair)
    path.chmod(0o644)

    with pytest.raises(SignerError, match="group/world accessible"):
        load_private_key(path)


def test_permission_check_can_be_relaxed_explicitly(tmp_path, signing_keypair):
    path = write_private_key(tmp_path / "node.key", signing_keypair)
    if os.name != "nt":
        path.chmod(0o644)

    assert load_private_key(path, require_strict_permissions=False)


def test_loading_a_missing_key_raises(tmp_path):
    with pytest.raises(SignerError, match="not found"):
        load_private_key(tmp_path / "absent.key")


def test_loading_an_empty_key_raises(tmp_path):
    path = tmp_path / "empty.key"
    path.touch(mode=0o600)

    with pytest.raises(SignerError, match="empty"):
        load_private_key(path)


def test_a_key_pair_never_prints_its_private_half(signing_keypair):
    assert "redacted" in repr(signing_keypair)
    assert signing_keypair.private_bytes.hex()[:32] not in repr(signing_keypair)


# -- backend safety ---------------------------------------------------------


def test_signer_rejects_an_empty_private_key(tmp_path, pqc_backend):
    with pytest.raises(SignerError, match="must not be empty"):
        EvidenceSigner(NODE_ID, KEY_ID, b"", tmp_path / "s.json", backend=pqc_backend)


def test_a_test_only_key_cannot_be_used_with_a_real_backend(tmp_path, pqc_backend):
    fake = TEST_KEY_MARKER + b"-000"

    with pytest.raises(SignerError, match="INSECURE-TEST-ONLY"):
        EvidenceSigner(NODE_ID, KEY_ID, fake, tmp_path / "s.json", backend=pqc_backend)


def test_the_test_backend_is_never_selected_implicitly():
    backend = select_backend(algorithm="ML-DSA-65")

    assert backend.name != TEST_BACKEND
    assert backend.capabilities().real_pqc is True


def test_requesting_the_test_backend_without_permission_fails():
    with pytest.raises(BackendUnavailableError, match="provides no security"):
        select_backend(name=TEST_BACKEND)


def test_production_mode_disables_the_test_backend(monkeypatch):
    monkeypatch.setenv("ICS_PQC_PRODUCTION", "1")

    capabilities = get_backend(TEST_BACKEND).capabilities()

    assert capabilities.available is False
    assert "ICS_PQC_PRODUCTION" in capabilities.reason


def test_the_backend_is_chosen_from_the_private_key_format(signing_keypair):
    # A key must go to the backend that can parse its format, whichever that is.
    backend = select_backend(for_private_key=signing_keypair.private_bytes)

    is_pem = signing_keypair.private_bytes.lstrip().startswith(b"-----BEGIN")
    assert backend.name == ("openssl" if is_pem else "pyfips")


def test_a_pem_private_key_selects_the_openssl_backend(openssl_backend):
    keypair = openssl_backend.generate_keypair("ML-DSA-65")

    assert keypair.private_bytes.lstrip().startswith(b"-----BEGIN")
    assert select_backend(for_private_key=keypair.private_bytes).name == "openssl"
