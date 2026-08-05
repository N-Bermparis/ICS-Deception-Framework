"""Chain state: atomicity, locking, corruption detection and sequence safety."""

from __future__ import annotations

import json
import os
import stat
import threading
import time

import pytest

from ics_deception.pqc_evidence.state_store import (
    NodeState,
    StateCorruptionError,
    StateLockError,
    StateStore,
    StateStoreError,
    locked_state,
)

NODE = "rpi-honeypot-01"
KEY = "rpi-honeypot-01-2026-01"
HASH_A = "a" * 64
HASH_B = "b" * 64


# -- basics -----------------------------------------------------------------


def test_a_missing_state_file_reads_as_a_fresh_chain(tmp_path):
    with StateStore(tmp_path / "state.json", NODE, KEY) as store:
        state = store.read()

    assert state.last_sequence == 0
    assert state.last_event_hash is None


def test_commit_then_read_round_trips(tmp_path):
    path = tmp_path / "state.json"
    with StateStore(path, NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)

    with StateStore(path, NODE, KEY) as store:
        state = store.read()

    assert state.last_sequence == 1
    assert state.last_event_hash == HASH_A
    assert state.node_id == NODE
    assert state.key_id == KEY
    assert state.updated_at


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_the_state_file_is_owner_only(tmp_path):
    path = tmp_path / "state.json"
    with StateStore(path, NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_writing_leaves_no_temporary_files(tmp_path):
    path = tmp_path / "state.json"
    with StateStore(path, NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)

    leftovers = [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


def test_operations_require_the_lock(tmp_path):
    store = StateStore(tmp_path / "state.json", NODE, KEY)

    with pytest.raises(StateStoreError, match="not locked"):
        store.read()


# -- sequence safety --------------------------------------------------------


def test_reusing_a_sequence_number_is_refused(tmp_path):
    with StateStore(tmp_path / "state.json", NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)

        with pytest.raises(StateStoreError, match="already at"):
            store.commit(1, HASH_B)


def test_going_backwards_is_refused(tmp_path):
    with StateStore(tmp_path / "state.json", NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)
        store.commit(2, HASH_B)

        with pytest.raises(StateStoreError, match="already at"):
            store.commit(2, HASH_A)


def test_skipping_a_sequence_is_refused(tmp_path):
    with StateStore(tmp_path / "state.json", NODE, KEY) as store:
        store.read()

        with pytest.raises(StateStoreError, match="no gaps"):
            store.commit(5, HASH_A)


def test_reset_starts_a_new_chain(tmp_path):
    path = tmp_path / "state.json"
    with StateStore(path, NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)
        store.commit(2, HASH_B)

        fresh = store.reset()

    assert fresh.last_sequence == 0
    assert fresh.last_event_hash is None


def test_recovery_can_move_forward(tmp_path):
    path = tmp_path / "state.json"
    with StateStore(path, NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)

        recovered = store.recover_from(7, HASH_B)

    assert recovered.last_sequence == 7
    assert recovered.last_event_hash == HASH_B


def test_recovery_refuses_to_rewind(tmp_path):
    path = tmp_path / "state.json"
    with StateStore(path, NODE, KEY) as store:
        store.read()
        store.commit(1, HASH_A)
        store.commit(2, HASH_B)

        with pytest.raises(StateStoreError, match="would reuse sequence numbers"):
            store.recover_from(1, HASH_A)


# -- corruption -------------------------------------------------------------


def test_truncated_state_is_detected(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"node_id": "rpi", "last_seq', encoding="utf-8")

    with StateStore(path, NODE, KEY) as store, pytest.raises(StateCorruptionError, match="truncated"):
        store.read()


def test_empty_state_is_detected(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("", encoding="utf-8")

    with StateStore(path, NODE, KEY) as store, pytest.raises(StateCorruptionError, match="empty"):
        store.read()


def test_state_belonging_to_another_node_is_refused(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "node_id": "some-other-node",
                "key_id": KEY,
                "last_sequence": 3,
                "last_event_hash": HASH_A,
                "format_version": "1.0",
            }
        ),
        encoding="utf-8",
    )

    with StateStore(path, NODE, KEY) as store, pytest.raises(
        StateCorruptionError, match="another node's chain state"
    ):
        store.read()


@pytest.mark.parametrize(
    "payload",
    [
        {"node_id": NODE, "key_id": KEY, "last_sequence": -1, "format_version": "1.0"},
        {"node_id": NODE, "key_id": KEY, "last_sequence": "3", "format_version": "1.0"},
        {"node_id": NODE, "key_id": KEY, "last_sequence": 3, "format_version": "9.9"},
        {"node_id": "", "key_id": KEY, "last_sequence": 0, "format_version": "1.0"},
        {"node_id": NODE, "key_id": "", "last_sequence": 0, "format_version": "1.0"},
        {
            "node_id": NODE,
            "key_id": KEY,
            "last_sequence": 3,
            "last_event_hash": "nothex",
            "format_version": "1.0",
        },
        # Claims events but carries no hash.
        {"node_id": NODE, "key_id": KEY, "last_sequence": 3, "format_version": "1.0"},
        # Claims no events but carries a hash.
        {
            "node_id": NODE,
            "key_id": KEY,
            "last_sequence": 0,
            "last_event_hash": HASH_A,
            "format_version": "1.0",
        },
    ],
)
def test_inconsistent_state_is_detected(tmp_path, payload):
    path = tmp_path / "state.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with StateStore(path, NODE, KEY) as store, pytest.raises(StateCorruptionError):
        store.read()


def test_an_implausibly_large_state_file_is_refused(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("x" * (64 * 1024 + 10), encoding="utf-8")

    with StateStore(path, NODE, KEY) as store, pytest.raises(StateCorruptionError, match="corruption"):
        store.read()


def test_node_state_from_dict_rejects_a_non_object():
    with pytest.raises(StateCorruptionError):
        NodeState.from_dict(["not", "a", "dict"])


# -- locking ----------------------------------------------------------------


def test_a_second_signer_cannot_take_the_lock(tmp_path):
    path = tmp_path / "state.json"
    first = StateStore(path, NODE, KEY, lock_timeout=0.2)
    first.acquire()
    try:
        with pytest.raises(StateLockError, match="another process holds"):
            StateStore(path, NODE, KEY, lock_timeout=0.2).acquire()
    finally:
        first.release()


def test_the_lock_is_released_on_exit(tmp_path):
    path = tmp_path / "state.json"
    with StateStore(path, NODE, KEY, lock_timeout=0.2):
        pass

    second = StateStore(path, NODE, KEY, lock_timeout=0.2)
    second.acquire()
    second.release()


def test_the_lock_is_released_even_when_the_block_raises(tmp_path):
    path = tmp_path / "state.json"
    with pytest.raises(RuntimeError), StateStore(path, NODE, KEY, lock_timeout=0.2):
        raise RuntimeError("boom")

    second = StateStore(path, NODE, KEY, lock_timeout=0.2)
    second.acquire()
    second.release()


def test_concurrent_threads_serialise_and_never_reuse_a_sequence(tmp_path):
    path = tmp_path / "state.json"
    committed: list[int] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(5):
            try:
                with StateStore(path, NODE, KEY, lock_timeout=10.0) as store:
                    state = store.read()
                    nxt = state.last_sequence + 1
                    time.sleep(0.001)  # widen the window for a race
                    store.commit(nxt, f"{nxt:064x}")
                    with lock:
                        committed.append(nxt)
            except Exception as exc:  # noqa: BLE001 - recorded and asserted below
                with lock:
                    errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, f"unexpected errors: {errors}"
    assert len(committed) == len(set(committed)), "a sequence number was issued twice"
    assert sorted(committed) == list(range(1, len(committed) + 1))


def test_locked_state_helper_yields_a_locked_store(tmp_path):
    with locked_state(tmp_path / "state.json", NODE, KEY) as store:
        assert store.read().last_sequence == 0
