"""Crash recovery, concurrency ordering and provider-absence behaviour.

Faults are injected at every stage of the signing transaction using the
``fault`` hook, which raises at a named point exactly as a crash would.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import threading

import pytest

from ics_deception.pqc_evidence.collector import EvidenceCollector
from ics_deception.pqc_evidence.crypto_backend import (
    BackendUnavailableError,
    Capabilities,
    get_backend,
    select_backend,
)
from ics_deception.pqc_evidence.evidence_store import (
    EvidenceStateDivergence,
    EvidenceStore,
    TransactionAborted,
)
from ics_deception.pqc_evidence.signer import EvidenceSigner
from ics_deception.pqc_evidence.state_store import StateCorruptionError, StateLockError
from tests.pqc_evidence.conftest import KEY_ID, NODE_ID

pytestmark = pytest.mark.pqc


def make_signer(tmp_path, keypair, backend, lock_timeout: float = 30.0) -> EvidenceSigner:
    """A signer rooted in ``tmp_path``."""
    return EvidenceSigner(
        NODE_ID,
        KEY_ID,
        keypair.private_bytes,
        tmp_path / "state.json",
        tmp_path / "evidence.jsonl",
        backend=backend,
        lock_timeout=lock_timeout,
    )


def sequences_in(path) -> list[int]:
    """Sequence numbers in physical file order."""
    if not path.is_file():
        return []
    return [
        json.loads(line)["sequence"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class Boom(RuntimeError):
    """Simulated crash."""


def crash_at(stage: str):
    """Return a fault hook that raises at exactly one transaction stage."""

    def hook(current: str) -> None:
        if current == stage:
            raise Boom(f"simulated crash at {stage}")

    return hook


# ===========================================================================
# Ordering
# ===========================================================================


def test_concurrent_threads_cannot_reorder_sequences(tmp_path, signing_keypair, pqc_backend):
    """The append happens inside the allocation lock, so file order is sequence order.

    The previous design allocated under the lock and let the caller append
    afterwards; two threads then reliably wrote sequence 2 before sequence 1.
    """
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    errors: list[Exception] = []
    barrier = threading.Barrier(4)

    def worker(index: int) -> None:
        try:
            barrier.wait(timeout=30)
            for _ in range(3):
                signer.sign_event({"source": "s", "event_type": "t", "worker": index})
        except Exception as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert not errors, f"unexpected errors: {errors}"
    observed = sequences_in(tmp_path / "evidence.jsonl")
    assert observed == sorted(observed), f"records persisted out of order: {observed}"
    assert observed == list(range(1, 13)), observed


def test_the_chain_verifies_after_concurrent_generation(
    tmp_path, signing_keypair, pqc_backend, registry
):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)

    def worker() -> None:
        for _ in range(3):
            signer.sign_event({"source": "s", "event_type": "concurrent"})

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    lines = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    report = EvidenceCollector(registry).verify_stream(lines)

    assert report.valid is True, report.alert_counts
    assert report.verified == 9


def _sign_in_subprocess(state: str, evidence: str, key: bytes, count: int, results) -> None:
    """Worker process: sign with its own signer against the shared node identity."""
    from ics_deception.pqc_evidence.crypto_backend import select_backend as _select
    from ics_deception.pqc_evidence.signer import EvidenceSigner as _Signer

    signer = _Signer(
        NODE_ID,
        KEY_ID,
        key,
        state,
        evidence,
        backend=_select(for_private_key=key),
        lock_timeout=60.0,
    )
    for _ in range(count):
        results.append(signer.sign_event({"source": "s", "event_type": "mp"}).sequence)


def test_two_processes_cannot_allocate_duplicate_sequences(tmp_path, signing_keypair):
    """The lock is a file lock, so it holds across processes, not just threads."""
    state = str(tmp_path / "state.json")
    evidence = str(tmp_path / "evidence.jsonl")
    manager = multiprocessing.Manager()
    results = manager.list()

    processes = [
        multiprocessing.Process(
            target=_sign_in_subprocess,
            args=(state, evidence, signing_keypair.private_bytes, 3, results),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=180)
    for process in processes:
        assert process.exitcode == 0, "a concurrent signer process failed"

    issued = sorted(results)
    assert issued == list(range(1, 7)), issued
    observed = sequences_in(tmp_path / "evidence.jsonl")
    assert observed == sorted(observed), f"records persisted out of order: {observed}"
    assert observed == list(range(1, 7))


# ===========================================================================
# Crash recovery — one test per transaction stage
# ===========================================================================


def test_a_crash_before_signing_leaves_nothing_behind(tmp_path, signing_keypair, pqc_backend):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)

    with pytest.raises(Boom):
        signer.sign_event({"source": "s", "event_type": "t"}, fault=crash_at("before_sign"))

    assert sequences_in(tmp_path / "evidence.jsonl") == []
    # The sequence was never consumed.
    assert signer.sign_event({"source": "s", "event_type": "t"}).sequence == 1


def test_a_crash_after_signing_before_append_reissues_the_sequence(
    tmp_path, signing_keypair, pqc_backend, registry
):
    """Signed but never durably written: the record simply never existed."""
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "first"})

    with pytest.raises(Boom):
        signer.sign_event({"source": "s", "event_type": "lost"}, fault=crash_at("after_sign"))

    following = signer.sign_event({"source": "s", "event_type": "after"})
    assert following.sequence == 2, "the unwritten sequence must be reissued, not skipped"

    lines = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    report = EvidenceCollector(registry).verify_stream(lines)
    assert report.valid is True, report.alert_counts


def test_a_crash_after_the_journal_rolls_back(tmp_path, signing_keypair, pqc_backend, registry):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "first"})

    with pytest.raises(Boom):
        signer.sign_event({"source": "s", "event_type": "lost"}, fault=crash_at("after_journal"))

    # A journal is left behind; the next open must roll it back.
    assert (tmp_path / "state.json.journal").is_file()
    following = signer.sign_event({"source": "s", "event_type": "after"})

    assert following.sequence == 2
    assert not (tmp_path / "state.json.journal").is_file()
    lines = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    assert EvidenceCollector(registry).verify_stream(lines).valid is True


def test_a_crash_after_append_before_commit_completes_on_recovery(
    tmp_path, signing_keypair, pqc_backend, registry
):
    """The record is durable, so recovery finishes the commit rather than losing it."""
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "first"})

    with pytest.raises(Boom):
        signer.sign_event({"source": "s", "event_type": "durable"}, fault=crash_at("after_append"))

    # Reopening recovers: the appended record is adopted, not discarded.
    with signer.store() as store:
        report = store.last_recovery
        assert report is not None
        assert report.action in ("completed_commit", "already_committed")
        assert store.read_state().last_sequence == 2

    following = signer.sign_event({"source": "s", "event_type": "after"})
    assert following.sequence == 3, "a durably appended record must not be overwritten"

    lines = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    assert sequences_in(tmp_path / "evidence.jsonl") == [1, 2, 3]
    assert EvidenceCollector(registry).verify_stream(lines).valid is True


def test_a_crash_after_commit_before_journal_cleanup_is_idempotent(
    tmp_path, signing_keypair, pqc_backend, registry
):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "first"})

    with pytest.raises(Boom):
        signer.sign_event({"source": "s", "event_type": "committed"}, fault=crash_at("after_commit"))

    with signer.store() as store:
        assert store.last_recovery.action in ("completed_commit", "already_committed")
        assert store.read_state().last_sequence == 2

    following = signer.sign_event({"source": "s", "event_type": "after"})
    assert following.sequence == 3
    assert sequences_in(tmp_path / "evidence.jsonl") == [1, 2, 3]
    lines = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    assert EvidenceCollector(registry).verify_stream(lines).valid is True


def test_a_partial_append_is_truncated_and_preserved(tmp_path, signing_keypair, pqc_backend):
    """A half-written record is removed, and the discarded bytes are kept for analysis."""
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "first"})

    with pytest.raises(Boom):
        signer.sign_event({"source": "s", "event_type": "partial"}, fault=crash_at("after_journal"))

    # Simulate the partial write the crash would have left.
    evidence = tmp_path / "evidence.jsonl"
    offset = evidence.stat().st_size
    with open(evidence, "a", encoding="utf-8") as handle:
        handle.write('{"format_version":"1.0","node_id":"rpi-hon')

    with signer.store() as store:
        report = store.last_recovery

    assert report.action == "rolled_back_partial_append"
    assert report.bytes_discarded > 0
    assert report.preserved_path is not None
    assert os.path.isfile(report.preserved_path), "discarded bytes must be preserved"
    assert evidence.stat().st_size == offset


def test_a_failed_disk_write_does_not_advance_state(tmp_path, signing_keypair, pqc_backend):
    """An append that fails must leave state exactly where it was."""
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "first"})

    real_open = open

    def failing_open(path, mode="r", *args, **kwargs):
        if str(path).endswith("evidence.jsonl") and "a" in mode:
            raise OSError(28, "No space left on device")
        return real_open(path, mode, *args, **kwargs)

    import builtins

    builtins.open = failing_open
    try:
        with pytest.raises(TransactionAborted, match="could not append"):
            signer.sign_event({"source": "s", "event_type": "doomed"})
    finally:
        builtins.open = real_open

    with signer.store() as store:
        assert store.read_state().last_sequence == 1, "state advanced despite a failed write"
    assert signer.sign_event({"source": "s", "event_type": "after"}).sequence == 2


def test_state_ahead_of_the_log_is_refused_not_papered_over(
    tmp_path, signing_keypair, pqc_backend
):
    """Missing signed evidence cannot be repaired silently."""
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    for _ in range(3):
        signer.sign_event({"source": "s", "event_type": "t"})

    # Evidence lost, state retained — the dangerous direction.
    (tmp_path / "evidence.jsonl").unlink()

    with (
        pytest.raises(EvidenceStateDivergence, match="cannot be repaired automatically"),
        signer.store(),
    ):
        pass


def test_explicit_repair_rebuilds_state_from_the_log(tmp_path, signing_keypair, pqc_backend):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    for _ in range(3):
        signer.sign_event({"source": "s", "event_type": "t"})

    (tmp_path / "state.json").unlink()
    repaired = signer.repair_state_from_log()

    assert repaired["last_sequence"] == 3
    assert signer.sign_event({"source": "s", "event_type": "after"}).sequence == 4


def test_a_corrupt_state_file_is_detected(tmp_path, signing_keypair, pqc_backend):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "t"})

    text = (tmp_path / "state.json").read_text(encoding="utf-8")
    (tmp_path / "state.json").write_text(text[: len(text) // 2], encoding="utf-8")

    with pytest.raises(StateCorruptionError), signer.store():
        pass


def test_an_unreadable_journal_is_preserved_and_rolled_back(
    tmp_path, signing_keypair, pqc_backend
):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    signer.sign_event({"source": "s", "event_type": "t"})
    (tmp_path / "state.json.journal").write_text("{ not json", encoding="utf-8")

    with signer.store() as store:
        report = store.last_recovery

    assert report.action == "discarded_unreadable_journal"
    assert report.preserved_path is not None


# ===========================================================================
# Locking
# ===========================================================================


def test_a_held_lock_blocks_a_second_signer_with_a_bounded_wait(
    tmp_path, signing_keypair, pqc_backend
):
    holder = EvidenceStore(
        tmp_path / "state.json", tmp_path / "evidence.jsonl", NODE_ID, KEY_ID, lock_timeout=0.2
    )
    holder.acquire()
    try:
        signer = make_signer(tmp_path, signing_keypair, pqc_backend, lock_timeout=0.2)
        with pytest.raises(StateLockError, match="timed out"):
            signer.sign_event({"source": "s", "event_type": "t"})
    finally:
        holder.release()


def test_the_lock_is_released_after_use(tmp_path, signing_keypair, pqc_backend):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend, lock_timeout=1.0)
    signer.sign_event({"source": "s", "event_type": "t"})

    store = EvidenceStore(
        tmp_path / "state.json", tmp_path / "evidence.jsonl", NODE_ID, KEY_ID, lock_timeout=1.0
    )
    store.acquire()
    store.release()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlinked_lock_path_is_refused(tmp_path, signing_keypair, pqc_backend):
    """A planted symlink must not redirect the lock somewhere else."""
    target = tmp_path / "elsewhere"
    target.write_text("", encoding="utf-8")
    (tmp_path / "state.json.lock").symlink_to(target)

    signer = make_signer(tmp_path, signing_keypair, pqc_backend, lock_timeout=0.5)
    with pytest.raises(StateLockError, match="symbolic link"):
        signer.sign_event({"source": "s", "event_type": "t"})


def test_a_zero_lock_timeout_is_rejected(tmp_path, signing_keypair, pqc_backend):
    from ics_deception.pqc_evidence.signer import SignerError

    with pytest.raises(SignerError, match="greater than zero"):
        make_signer(tmp_path, signing_keypair, pqc_backend, lock_timeout=0)


# ===========================================================================
# Provider absence
# ===========================================================================


def test_a_missing_provider_yields_a_structured_error(monkeypatch):
    """No silent fallback to a classical algorithm when ML-DSA is missing."""
    from ics_deception.pqc_evidence import crypto_backend as module

    monkeypatch.setattr(
        module.PyFipsBackend,
        "capabilities",
        lambda self: Capabilities(
            name="pyfips", available=False, reason="dilithium-py is not installed"
        ),
    )
    monkeypatch.setattr(
        module._registry()["openssl"].__class__,
        "capabilities",
        lambda self: Capabilities(
            name="openssl", available=False, reason="OpenSSL 3.0.2 does not implement ML-DSA"
        ),
    )

    with pytest.raises(BackendUnavailableError) as excinfo:
        select_backend(algorithm="ML-DSA-65")

    message = str(excinfo.value)
    assert "no backend can provide ML-DSA-65" in message
    assert "dilithium-py is not installed" in message
    assert "does not implement ML-DSA" in message
    assert "pip install" in message
    for classical in ("RSA", "ECDSA", "Ed25519", "HMAC"):
        assert classical not in message


def test_openssl_is_selected_when_pyfips_is_unavailable(monkeypatch, openssl_backend):
    """Losing the optional package must not lose real crypto when OpenSSL is present."""
    from ics_deception.pqc_evidence import crypto_backend as module

    monkeypatch.setattr(
        module.PyFipsBackend,
        "capabilities",
        lambda self: Capabilities(
            name="pyfips", available=False, reason="dilithium-py is not installed"
        ),
    )

    backend = module.select_real_backend(signature_algorithm="ML-DSA-65")

    assert backend.name == "openssl"
    assert backend.capabilities().real_pqc is True


def test_generic_selection_does_not_require_a_named_backend():
    """select_real_backend asks for a capability, never for one package."""
    from ics_deception.pqc_evidence.crypto_backend import real_backends, select_real_backend

    available = real_backends("ML-DSA-65")
    assert available, "no real backend at all; the environment is misconfigured"

    backend = select_real_backend(signature_algorithm="ML-DSA-65")
    assert backend.name in {b.name for b in available}
    assert backend.capabilities().real_pqc is True


def test_an_incorrect_provider_version_is_reported_clearly(monkeypatch):
    from ics_deception.pqc_evidence.openssl_backend import OpenSslBackend

    backend = OpenSslBackend()
    monkeypatch.setattr(
        backend,
        "_run",
        lambda args, stdin=None: type(
            "R", (), {"returncode": 0, "stdout": b"OpenSSL 3.0.2 15 Mar 2022\n", "stderr": b""}
        )(),
    )

    capabilities = backend._probe()

    assert capabilities.available is False
    assert "3.5" in capabilities.reason
    assert "ML-DSA" in capabilities.reason


def test_an_unknown_backend_name_is_rejected():
    from ics_deception.pqc_evidence.crypto_backend import BackendError

    with pytest.raises(BackendError, match="unknown crypto backend"):
        get_backend("magic-quantum-backend")


# ===========================================================================
# Cleanliness
# ===========================================================================


def test_signing_leaves_only_the_expected_files(tmp_path, signing_keypair, pqc_backend):
    signer = make_signer(tmp_path, signing_keypair, pqc_backend)
    for _ in range(3):
        signer.sign_event({"source": "s", "event_type": "t"})

    names = sorted(p.name for p in tmp_path.iterdir())

    assert names == ["evidence.jsonl", "state.json", "state.json.lock"], names
