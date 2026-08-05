"""Crash-safe per-node chain state.

The signer must never reuse a sequence number. If it did, two different events
would claim the same chain position and a verifier could not tell which is
authentic — exactly the forgery the chain exists to prevent. That makes the
state file the most safety-critical piece of mutable state in the package.

Guarantees
----------
Atomicity
    State is written to a temporary file in the same directory, ``fsync``-ed,
    then ``os.replace``-d. A crash leaves either the complete old state or the
    complete new one, never a half-written file.
Single writer
    An exclusive advisory lock (``fcntl.flock`` on POSIX, ``msvcrt.locking`` on
    Windows) is held for the whole read-modify-write cycle, so two signer
    processes using the same node identity cannot interleave and mint the same
    sequence number.
Corruption detection
    Every field is validated on load. Truncated JSON, a wrong node id, a
    negative sequence or a malformed hash all raise
    :class:`StateCorruptionError` rather than being silently repaired — silent
    repair of chain state is indistinguishable from tampering.
Ordering safety
    :meth:`StateStore.commit` refuses to move the sequence backwards.

Manual recovery
---------------
If the state file is lost or corrupted, the operator must decide explicitly,
because the tool cannot know whether the missing events were written:

* ``recover-from-log`` — rebuild state from the last valid record in the signed
  log (the normal case after a crash: the log is the authority).
* ``reset`` — start a new chain. This is a visible, auditable event: the
  verifier reports ``pqc_chain_reset`` when it sees a chain restart.

Never delete the state file to "fix" a problem; that silently invites sequence
reuse.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import EVIDENCE_FORMAT_VERSION, EvidenceError

__all__ = [
    "NodeState",
    "StateCorruptionError",
    "StateLockError",
    "StateStore",
    "StateStoreError",
]

#: Maximum size of a state file; anything larger is corruption, not state.
MAX_STATE_BYTES = 64 * 1024

_SHA3_HEX_LENGTH = 64


class StateStoreError(EvidenceError):
    """A state-store operation failed."""


class StateCorruptionError(StateStoreError):
    """The persisted state is unreadable or internally inconsistent."""


class StateLockError(StateStoreError):
    """Another process holds the state lock."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@dataclass
class NodeState:
    """Persisted chain position for one node."""

    node_id: str
    key_id: str
    last_sequence: int = 0
    last_event_hash: str | None = None
    format_version: str = EVIDENCE_FORMAT_VERSION
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot."""
        return {
            "node_id": self.node_id,
            "key_id": self.key_id,
            "last_sequence": self.last_sequence,
            "last_event_hash": self.last_event_hash,
            "format_version": self.format_version,
            "updated_at": self.updated_at or _utc_now(),
        }

    @staticmethod
    def from_dict(data: Any, expected_node_id: str | None = None) -> NodeState:
        """Validate untrusted state data.

        Every check raises :class:`StateCorruptionError`; nothing is repaired.
        """
        if not isinstance(data, dict):
            raise StateCorruptionError("state must be a JSON object")

        required = {"node_id", "key_id", "last_sequence", "format_version"}
        missing = required - set(data)
        if missing:
            raise StateCorruptionError(f"state is missing field(s): {sorted(missing)}")

        node_id = data["node_id"]
        if not isinstance(node_id, str) or not node_id:
            raise StateCorruptionError("state has an invalid node_id")
        if expected_node_id is not None and node_id != expected_node_id:
            raise StateCorruptionError(
                f"state belongs to node {node_id!r}, not {expected_node_id!r}; "
                "refusing to sign with another node's chain state"
            )

        key_id = data["key_id"]
        if not isinstance(key_id, str) or not key_id:
            raise StateCorruptionError("state has an invalid key_id")

        last_sequence = data["last_sequence"]
        if isinstance(last_sequence, bool) or not isinstance(last_sequence, int):
            raise StateCorruptionError("state last_sequence must be an integer")
        if last_sequence < 0:
            raise StateCorruptionError("state last_sequence must not be negative")

        last_event_hash = data.get("last_event_hash")
        if last_event_hash is not None and (
            not isinstance(last_event_hash, str)
            or len(last_event_hash) != _SHA3_HEX_LENGTH
            or any(c not in "0123456789abcdef" for c in last_event_hash)
        ):
            raise StateCorruptionError("state last_event_hash is not a SHA3-256 hex digest")
        if last_sequence > 0 and last_event_hash is None:
            raise StateCorruptionError(
                f"state claims sequence {last_sequence} but carries no last_event_hash"
            )
        if last_sequence == 0 and last_event_hash is not None:
            raise StateCorruptionError(
                "state claims no events yet but carries a last_event_hash"
            )

        format_version = data["format_version"]
        if format_version != EVIDENCE_FORMAT_VERSION:
            raise StateCorruptionError(
                f"state format_version {format_version!r} is not supported by this build "
                f"(expected {EVIDENCE_FORMAT_VERSION!r})"
            )

        return NodeState(
            node_id=node_id,
            key_id=key_id,
            last_sequence=last_sequence,
            last_event_hash=last_event_hash,
            format_version=format_version,
            updated_at=str(data.get("updated_at", "")),
        )


class StateStore:
    """Locked, atomic access to one node's chain state.

    Use as a context manager; the lock is held for the whole block::

        with StateStore(path, node_id="rpi-01", key_id="rpi-01-2026-01") as store:
            state = store.read()
            ...
            store.commit(sequence, event_hash)
    """

    def __init__(
        self,
        path: str | Path,
        node_id: str,
        key_id: str = "",
        lock_timeout: float = 10.0,
    ) -> None:
        self.path = Path(path).expanduser()
        self.node_id = node_id
        self.key_id = key_id
        self.lock_timeout = lock_timeout
        self._lock_handle: Any | None = None
        self._state: NodeState | None = None

    # -- locking -----------------------------------------------------------

    @property
    def lock_path(self) -> Path:
        """Path of the advisory lock file."""
        return self.path.with_name(self.path.name + ".lock")

    def acquire(self) -> None:
        """Take the exclusive lock, waiting up to ``lock_timeout`` seconds."""
        if self._lock_handle is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.lock_path, "a+b")  # noqa: SIM115 - lifetime is the lock's
        try:
            _lock_exclusive(handle, self.lock_timeout, self.lock_path)
        except BaseException:
            handle.close()
            raise
        with contextlib.suppress(OSError):  # pragma: no cover - best effort
            os.chmod(self.lock_path, 0o600)
        self._lock_handle = handle

    def release(self) -> None:
        """Release the lock, if held."""
        handle = self._lock_handle
        if handle is None:
            return
        self._lock_handle = None
        try:
            _unlock(handle)
        finally:
            handle.close()

    def __enter__(self) -> StateStore:
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()

    def _require_lock(self) -> None:
        if self._lock_handle is None:
            raise StateStoreError(
                "state store is not locked; use it as a context manager or call acquire()"
            )

    # -- read / write ------------------------------------------------------

    def exists(self) -> bool:
        """Whether a state file is present."""
        return self.path.is_file()

    def read(self) -> NodeState:
        """Load state, or return a fresh zero state when the file is absent."""
        self._require_lock()
        if not self.path.is_file():
            self._state = NodeState(node_id=self.node_id, key_id=self.key_id)
            return self._state
        try:
            size = self.path.stat().st_size
        except OSError as exc:
            raise StateStoreError(f"cannot stat state file {self.path}: {exc}") from exc
        if size > MAX_STATE_BYTES:
            raise StateCorruptionError(
                f"state file {self.path} is {size} bytes; that is corruption, not state"
            )
        try:
            raw = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise StateCorruptionError(f"cannot read state file {self.path}: {exc}") from exc
        if not raw.strip():
            raise StateCorruptionError(
                f"state file {self.path} is empty; a previous write was interrupted. "
                "Recover with 'ics-pqc-evidence' state recovery rather than deleting it."
            )
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StateCorruptionError(
                f"state file {self.path} is not valid JSON ({exc}); "
                "it was probably truncated by an interrupted write"
            ) from exc
        self._state = NodeState.from_dict(data, expected_node_id=self.node_id)
        return self._state

    def write(self, state: NodeState) -> None:
        """Persist state atomically with 0600 permissions."""
        self._require_lock()
        state.updated_at = _utc_now()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - atomic replace needs the name
            mode="w",
            encoding="utf-8",
            dir=str(self.path.parent),
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            delete=False,
        )
        temporary = handle.name
        try:
            with handle:
                json.dump(state.to_dict(), handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            _fsync_directory(self.path.parent)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise
        self._state = state

    def commit(self, sequence: int, event_hash: str, key_id: str | None = None) -> NodeState:
        """Advance the chain to ``sequence`` and persist it.

        Refuses to move backwards or skip ahead, so a bug elsewhere cannot
        cause sequence reuse.
        """
        self._require_lock()
        state = self._state if self._state is not None else self.read()
        if sequence <= state.last_sequence:
            raise StateStoreError(
                f"refusing to commit sequence {sequence}: node {self.node_id!r} is already at "
                f"{state.last_sequence}. Reusing a sequence number would break the chain."
            )
        if sequence != state.last_sequence + 1:
            raise StateStoreError(
                f"refusing to commit sequence {sequence}: expected "
                f"{state.last_sequence + 1} (no gaps are allowed in a chain)"
            )
        updated = NodeState(
            node_id=state.node_id or self.node_id,
            key_id=key_id or self.key_id or state.key_id,
            last_sequence=sequence,
            last_event_hash=event_hash,
            format_version=EVIDENCE_FORMAT_VERSION,
        )
        self.write(updated)
        return updated

    def reset(self, key_id: str | None = None) -> NodeState:
        """Start a new chain for this node.

        Deliberately explicit: a verifier will report ``pqc_chain_reset`` when
        it sees the restart, and that is the intended, visible outcome.
        """
        self._require_lock()
        fresh = NodeState(node_id=self.node_id, key_id=key_id or self.key_id)
        self.write(fresh)
        return fresh

    def recover_from(self, sequence: int, event_hash: str, key_id: str | None = None) -> NodeState:
        """Rebuild state from an externally verified chain position.

        Used after a crash when the signed log is ahead of the state file: the
        log is the authority, so state is moved forward to match it. Moving
        *backwards* is refused.
        """
        self._require_lock()
        current = self.read()
        if sequence < current.last_sequence:
            raise StateStoreError(
                f"refusing to rewind node {self.node_id!r} from sequence "
                f"{current.last_sequence} to {sequence}: that would reuse sequence numbers"
            )
        recovered = NodeState(
            node_id=self.node_id,
            key_id=key_id or self.key_id or current.key_id,
            last_sequence=sequence,
            last_event_hash=event_hash,
            format_version=EVIDENCE_FORMAT_VERSION,
        )
        self.write(recovered)
        return recovered


# ---------------------------------------------------------------------------
# Platform-specific advisory locking
# ---------------------------------------------------------------------------


def _lock_exclusive(handle: Any, timeout: float, path: Path) -> None:
    """Acquire an exclusive advisory lock, or raise :class:`StateLockError`."""
    import time

    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        try:
            _try_lock(handle)
            return
        except BlockingIOError:
            pass
        except OSError as exc:  # pragma: no cover - unusual filesystems
            raise StateLockError(f"cannot lock {path}: {exc}") from exc
        if time.monotonic() >= deadline:
            raise StateLockError(
                f"another process holds the evidence state lock {path}. "
                "Two signers must not share one node identity; if the previous signer "
                "crashed, remove the lock file only after confirming it is not running."
            )
        time.sleep(0.05)


if os.name == "nt":  # pragma: no cover - POSIX is the deployment target

    def _try_lock(handle: Any) -> None:
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock(handle: Any) -> None:
        import msvcrt

        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass

else:

    def _try_lock(handle: Any) -> None:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(handle: Any) -> None:
        import fcntl

        with contextlib.suppress(OSError):  # pragma: no cover
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _fsync_directory(directory: Path) -> None:
    """Flush the directory entry so the rename survives a power loss."""
    if os.name == "nt":  # pragma: no cover - not supported on Windows
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover
        pass
    finally:
        os.close(fd)


@contextmanager
def locked_state(
    path: str | Path, node_id: str, key_id: str = "", lock_timeout: float = 10.0
) -> Iterator[StateStore]:
    """Convenience context manager yielding a locked :class:`StateStore`."""
    store = StateStore(path, node_id=node_id, key_id=key_id, lock_timeout=lock_timeout)
    with store:
        yield store
