"""Transactional, crash-safe, order-preserving evidence persistence.

The problem this solves
-----------------------
Signing an event touches two pieces of durable state: the **evidence log** (the
append-only JSONL file) and the **chain state** (the last sequence and hash).
If those are updated independently, two failures follow:

*Ordering.* If the signer allocates a sequence under a lock, releases it, and
lets the caller append afterwards, nothing binds file order to sequence order.
Two threads reliably produce ``sequence 2`` before ``sequence 1`` in the file.

*Durability.* If state is committed before the record is appended, a crash in
between leaves a permanently missing record. If the record is appended before
state is committed, a crash leaves the record with no state — and a naive
restart reuses its sequence number, which is indistinguishable from forgery.

The fix
-------
One component owns the lock, the journal, the log and the state, and performs
the whole operation as a single transaction::

    lock ──▶ recover ──▶ allocate ──▶ hash ──▶ sign ──▶ journal(fsync)
         ──▶ append(fsync) ──▶ commit state(atomic+fsync) ──▶ drop journal ──▶ unlock

Because the append happens *inside* the lock, immediately after allocation,
file order is sequence order by construction.

The journal is a write-ahead intent record: it names the sequence, the hash, the
exact byte offset the record will occupy, and the record itself. Recovery reads
it and can always tell which side of the append the crash fell on:

* **Record fully present at the offset** — the crash was after the append.
  Finish the transaction by committing state. Nothing is lost.
* **Record absent or partial** — the crash was during or before the append.
  Truncate back to the recorded offset (preserving the discarded bytes first)
  and leave state untouched. The sequence is reused, which is safe precisely
  because no complete signed record ever claimed it.

That ordering — journal, then append, then commit — is what makes "no committed
state without a durable evidence record" an invariant rather than a hope.

What is *not* automatic
-----------------------
If committed state is **ahead** of the log (state says sequence 40, the log
ends at 30), the evidence was lost after being committed. That cannot be
repaired from inside: the signed records are simply gone. Recovery stops with
:class:`EvidenceStateDivergence` and an explicit administrative command is
required, because silently continuing would either reuse sequence numbers or
paper over the loss.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import EVIDENCE_FORMAT_VERSION, EvidenceError
from ics_deception.pqc_evidence.state_store import (
    NodeState,
    StateCorruptionError,
    StateLockError,
)

__all__ = [
    "EvidenceStateDivergence",
    "EvidenceStore",
    "EvidenceStoreError",
    "RecoveryReport",
    "TransactionAborted",
]

#: Maximum size of a journal file. A journal holds one record plus metadata.
MAX_JOURNAL_BYTES = 1024 * 1024

#: Default bound on how long a writer waits for the lock, in seconds.
DEFAULT_LOCK_TIMEOUT = 10.0

_POSIX = os.name != "nt"


class EvidenceStoreError(EvidenceError):
    """A transactional evidence operation failed."""


class TransactionAborted(EvidenceStoreError):
    """The transaction was rolled back; nothing was committed."""


class EvidenceStateDivergence(EvidenceStoreError):
    """Committed state and the evidence log disagree irreparably.

    Raised when state claims events the log does not contain. Requires an
    explicit operator decision — see ``ics-pqc-evidence recover-state``.
    """


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@dataclass
class RecoveryReport:
    """What recovery found and did when the store was opened."""

    journal_found: bool = False
    action: str = "none"
    sequence: int | None = None
    bytes_discarded: int = 0
    preserved_path: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable report."""
        return {
            "journal_found": self.journal_found,
            "action": self.action,
            "sequence": self.sequence,
            "bytes_discarded": self.bytes_discarded,
            "preserved_path": self.preserved_path,
            "detail": self.detail,
        }


def _fsync_path(path: Path) -> None:
    """Flush a file's contents to stable storage."""
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _fsync_dir(directory: Path) -> None:
    """Flush a directory entry, so a rename or unlink survives power loss."""
    if not _POSIX:  # pragma: no cover - Windows cannot fsync a directory
        return
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class EvidenceStore:
    """Owns the lock, journal, evidence log and chain state for one node.

    Use as a context manager; the exclusive lock is held for the whole block::

        with EvidenceStore(state_path, evidence_path, node_id, key_id) as store:
            record = store.append_signed(build_and_sign)
    """

    def __init__(
        self,
        state_path: str | Path,
        evidence_path: str | Path,
        node_id: str,
        key_id: str = "",
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> None:
        if lock_timeout <= 0:
            raise EvidenceStoreError("lock_timeout must be greater than zero")
        self.state_path = Path(state_path).expanduser()
        self.evidence_path = Path(evidence_path).expanduser()
        self.node_id = node_id
        self.key_id = key_id
        self.lock_timeout = lock_timeout
        self._lock_fd: int | None = None
        self._state: NodeState | None = None
        self.last_recovery: RecoveryReport | None = None

    # -- paths -------------------------------------------------------------

    @property
    def lock_path(self) -> Path:
        """Advisory lock file guarding this node's evidence and state."""
        return self.state_path.with_name(self.state_path.name + ".lock")

    @property
    def journal_path(self) -> Path:
        """Write-ahead journal describing an in-flight transaction."""
        return self.state_path.with_name(self.state_path.name + ".journal")

    # -- locking -----------------------------------------------------------

    def acquire(self) -> None:
        """Take the exclusive lock, waiting at most ``lock_timeout`` seconds.

        The lock file is opened with ``O_NOFOLLOW`` so a symlink planted at the
        lock path cannot redirect the writer somewhere else, and with mode 0600.
        """
        if self._lock_fd is not None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)

        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise StateLockError(
                    f"refusing to use {self.lock_path}: it is a symbolic link"
                ) from exc
            raise EvidenceStoreError(f"cannot open lock {self.lock_path}: {exc}") from exc

        try:
            self._verify_lock_file(fd)
            _lock_exclusive(fd, self.lock_timeout, self.lock_path)
        except BaseException:
            os.close(fd)
            raise
        self._lock_fd = fd

    def _verify_lock_file(self, fd: int) -> None:
        """Reject a lock file that is not a plain, owner-only regular file."""
        if not _POSIX:  # pragma: no cover - Windows permission model differs
            return
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise StateLockError(f"lock path {self.lock_path} is not a regular file")
        if info.st_uid != os.getuid():
            raise StateLockError(
                f"lock file {self.lock_path} is owned by uid {info.st_uid}, not {os.getuid()}"
            )
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)

    def release(self) -> None:
        """Release the lock, if held."""
        fd = self._lock_fd
        if fd is None:
            return
        self._lock_fd = None
        try:
            _unlock(fd)
        finally:
            os.close(fd)

    def __enter__(self) -> EvidenceStore:
        self.acquire()
        self.recover()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()

    def _require_lock(self) -> None:
        if self._lock_fd is None:
            raise EvidenceStoreError(
                "evidence store is not locked; use it as a context manager"
            )

    # -- state -------------------------------------------------------------

    def read_state(self) -> NodeState:
        """Load committed state, or a fresh zero state when absent."""
        self._require_lock()
        if self._state is not None:
            return self._state
        if not self.state_path.is_file():
            self._state = NodeState(node_id=self.node_id, key_id=self.key_id)
            return self._state
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise StateCorruptionError(f"cannot read state {self.state_path}: {exc}") from exc
        if not raw.strip():
            raise StateCorruptionError(
                f"state file {self.state_path} is empty; a write was interrupted. "
                "Run 'ics-pqc-evidence recover-state' rather than deleting it."
            )
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StateCorruptionError(
                f"state file {self.state_path} is not valid JSON ({exc}); "
                "it was probably truncated by an interrupted write"
            ) from exc
        self._state = NodeState.from_dict(data, expected_node_id=self.node_id)
        return self._state

    def _write_state(self, state: NodeState) -> None:
        """Persist state atomically with fsync and 0600 permissions."""
        state.updated_at = _utc_now()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - atomic replace needs the name
            mode="w",
            encoding="utf-8",
            dir=str(self.state_path.parent),
            prefix=f".{self.state_path.name}.",
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
            os.replace(temporary, self.state_path)
            _fsync_dir(self.state_path.parent)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise
        self._state = state

    # -- recovery ----------------------------------------------------------

    def recover(self) -> RecoveryReport:
        """Complete or roll back any interrupted transaction.

        Called automatically on entering the context manager. Safe to call
        repeatedly: with no journal it is a cheap consistency check.
        """
        self._require_lock()
        report = RecoveryReport()

        if self.journal_path.is_file():
            report = self._replay_journal()
        self._check_state_against_log(report)

        self.last_recovery = report
        return report

    def _replay_journal(self) -> RecoveryReport:
        report = RecoveryReport(journal_found=True)
        try:
            size = self.journal_path.stat().st_size
            if size > MAX_JOURNAL_BYTES:
                raise StateCorruptionError(
                    f"journal {self.journal_path} is {size} bytes; that is corruption"
                )
            entry = json.loads(self.journal_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            # A journal we cannot read is itself evidence of an interrupted
            # write. Preserve it and roll back conservatively.
            preserved = self._preserve(self.journal_path, "journal")
            self._drop_journal()
            report.action = "discarded_unreadable_journal"
            report.preserved_path = preserved
            report.detail = f"journal was unreadable ({exc}); no state was advanced"
            return report

        required = {"sequence", "event_hash", "offset", "record", "node_id"}
        missing = required - set(entry)
        if missing or entry.get("node_id") != self.node_id:
            preserved = self._preserve(self.journal_path, "journal")
            self._drop_journal()
            report.action = "discarded_foreign_journal"
            report.preserved_path = preserved
            report.detail = f"journal was incomplete or belonged to another node: {sorted(missing)}"
            return report

        sequence = int(entry["sequence"])
        offset = int(entry["offset"])
        expected_line = str(entry["record"]) + "\n"
        report.sequence = sequence

        actual_size = self.evidence_path.stat().st_size if self.evidence_path.is_file() else 0

        if actual_size >= offset + len(expected_line.encode("utf-8")):
            with open(self.evidence_path, "rb") as handle:
                handle.seek(offset)
                written = handle.read(len(expected_line.encode("utf-8")))
            if written == expected_line.encode("utf-8"):
                # The append completed. Finish the transaction.
                state = self.read_state()
                if state.last_sequence < sequence:
                    self._write_state(
                        NodeState(
                            node_id=self.node_id,
                            key_id=entry.get("key_id") or self.key_id or state.key_id,
                            last_sequence=sequence,
                            last_event_hash=str(entry["event_hash"]),
                            format_version=EVIDENCE_FORMAT_VERSION,
                        )
                    )
                    report.action = "completed_commit"
                    report.detail = (
                        f"record {sequence} was durably appended before the crash; "
                        "state has been advanced to match"
                    )
                else:
                    report.action = "already_committed"
                    report.detail = f"record {sequence} and state were both already durable"
                self._drop_journal()
                return report

        # The append never completed. Roll back to the recorded offset.
        discarded = max(0, actual_size - offset)
        preserved = None
        if discarded:
            preserved = self._preserve_tail(offset, discarded)
        self._truncate_evidence(offset)
        self._drop_journal()
        report.action = "rolled_back_partial_append"
        report.bytes_discarded = discarded
        report.preserved_path = preserved
        report.detail = (
            f"record {sequence} was not durably appended; {discarded} partial byte(s) "
            "removed and the sequence will be reissued"
        )
        return report

    def _check_state_against_log(self, report: RecoveryReport) -> None:
        """Refuse to continue when state claims events the log does not hold."""
        state = self.read_state()
        if state.last_sequence == 0:
            return
        last_logged = self._last_logged_sequence()
        if last_logged is None or last_logged < state.last_sequence:
            raise EvidenceStateDivergence(
                f"node {self.node_id!r}: committed state is at sequence "
                f"{state.last_sequence} but the evidence log "
                f"{self.evidence_path} ends at "
                f"{last_logged if last_logged is not None else 'no records'}. "
                "Signed evidence is missing; this cannot be repaired automatically. "
                "Inspect the log, then run 'ics-pqc-evidence recover-state --help'."
            )
        if last_logged > state.last_sequence:
            # Extra complete records beyond state: adopt them rather than
            # reissuing their sequence numbers.
            tail = self._last_logged_record()
            if tail is not None:
                self._write_state(
                    NodeState(
                        node_id=self.node_id,
                        key_id=self.key_id or state.key_id,
                        last_sequence=int(tail["sequence"]),
                        last_event_hash=str(tail["event_hash"]),
                        format_version=EVIDENCE_FORMAT_VERSION,
                    )
                )
                report.action = report.action or "adopted_log_tail"
                report.detail += (
                    f" evidence log was ahead of state; state advanced to {tail['sequence']}"
                )

    def _last_logged_record(self) -> dict[str, Any] | None:
        """Return the last complete record for this node, or ``None``."""
        if not self.evidence_path.is_file():
            return None
        last: dict[str, Any] | None = None
        try:
            with open(self.evidence_path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        record = json.loads(text)
                    except (json.JSONDecodeError, ValueError):
                        continue  # a partial tail line is not a complete record
                    if (
                        isinstance(record, dict)
                        and record.get("node_id") == self.node_id
                        and isinstance(record.get("sequence"), int)
                        and isinstance(record.get("event_hash"), str)
                    ):
                        last = record
        except OSError as exc:  # pragma: no cover - unreadable log
            raise EvidenceStoreError(f"cannot read {self.evidence_path}: {exc}") from exc
        return last

    def _last_logged_sequence(self) -> int | None:
        record = self._last_logged_record()
        return int(record["sequence"]) if record else None

    def _preserve(self, path: Path, label: str) -> str | None:
        """Copy a file aside before discarding it, for later analysis."""
        if not path.is_file():
            return None
        target = path.with_name(f"{path.name}.{label}.corrupt-{int(time.time())}")
        with contextlib.suppress(OSError):
            target.write_bytes(path.read_bytes())
            os.chmod(target, 0o600)
            return str(target)
        return None  # pragma: no cover - preservation is best effort

    def _preserve_tail(self, offset: int, length: int) -> str | None:
        """Copy the bytes about to be truncated into a side file."""
        target = self.evidence_path.with_name(
            f"{self.evidence_path.name}.partial-{int(time.time())}"
        )
        try:
            with open(self.evidence_path, "rb") as handle:
                handle.seek(offset)
                data = handle.read(length)
            target.write_bytes(data)
            os.chmod(target, 0o600)
            return str(target)
        except OSError:  # pragma: no cover - preservation is best effort
            return None

    def _truncate_evidence(self, offset: int) -> None:
        with open(self.evidence_path, "r+b") as handle:
            handle.truncate(offset)
            handle.flush()
            os.fsync(handle.fileno())

    def _drop_journal(self) -> None:
        with contextlib.suppress(OSError):
            os.unlink(self.journal_path)
        _fsync_dir(self.journal_path.parent)

    # -- the transaction ---------------------------------------------------

    def append_signed(
        self,
        build_and_sign: Callable[[int, str], tuple[str, str]],
        key_id: str | None = None,
        fault: Callable[[str], None] | None = None,
    ) -> tuple[int, str]:
        """Allocate, sign, append and commit one event as one transaction.

        ``build_and_sign`` receives ``(sequence, previous_event_hash)`` and must
        return ``(record_line, event_hash)``. It runs *inside* the lock, so the
        record it produces is the next one physically written — that is what
        makes file order equal sequence order.

        ``fault`` is a test hook invoked at each transaction stage; raising from
        it simulates a crash at that exact point.

        Returns ``(sequence, event_hash)``.
        """
        self._require_lock()
        state = self.read_state()
        sequence = state.last_sequence + 1

        from ics_deception.pqc_evidence.event_chain import expected_previous_hash

        previous_hash = expected_previous_hash(
            self.node_id, sequence, state.last_event_hash
        )

        if fault:
            fault("before_sign")
        record_line, event_hash = build_and_sign(sequence, previous_hash)
        if not isinstance(record_line, str) or not isinstance(event_hash, str):
            raise EvidenceStoreError("build_and_sign must return (str, str)")
        if fault:
            fault("after_sign")

        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.evidence_path.exists():
            # Create with restrictive permissions before anything is written.
            fd = os.open(self.evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        offset = self.evidence_path.stat().st_size

        self._write_journal(sequence, event_hash, offset, record_line, key_id)
        if fault:
            fault("after_journal")

        payload = (record_line + "\n").encode("utf-8")
        try:
            with open(self.evidence_path, "ab") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            # The append failed. Roll back to the recorded offset and leave
            # state untouched: the sequence is reissued, never skipped.
            self._rollback(offset)
            raise TransactionAborted(
                f"could not append evidence record {sequence}: {exc}; "
                "state was not advanced and the sequence will be reissued"
            ) from exc
        if fault:
            fault("after_append")

        try:
            self._write_state(
                NodeState(
                    node_id=self.node_id,
                    key_id=key_id or self.key_id or state.key_id,
                    last_sequence=sequence,
                    last_event_hash=event_hash,
                    format_version=EVIDENCE_FORMAT_VERSION,
                )
            )
        except OSError as exc:
            # The record is durable but state is not. Leave the journal in
            # place: recovery will complete the commit on the next open.
            raise TransactionAborted(
                f"record {sequence} was appended but state could not be committed: {exc}; "
                "recovery will complete the commit on the next start"
            ) from exc
        if fault:
            fault("after_commit")

        self._drop_journal()
        return sequence, event_hash

    def _write_journal(
        self, sequence: int, event_hash: str, offset: int, record: str, key_id: str | None
    ) -> None:
        entry = {
            "node_id": self.node_id,
            "key_id": key_id or self.key_id,
            "sequence": sequence,
            "event_hash": event_hash,
            "offset": offset,
            "record": record,
            "written_at": _utc_now(),
        }
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(entry, handle)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise TransactionAborted(f"cannot write the evidence journal: {exc}") from exc
        _fsync_dir(self.journal_path.parent)

    def _rollback(self, offset: int) -> None:
        """Undo a partial append and remove the journal."""
        with contextlib.suppress(OSError):
            if self.evidence_path.is_file() and self.evidence_path.stat().st_size > offset:
                self._truncate_evidence(offset)
        self._drop_journal()

    # -- administrative ----------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Return a status snapshot with no secret material."""
        self._require_lock()
        state = self.read_state()
        return {
            "node_id": self.node_id,
            "key_id": state.key_id,
            "last_sequence": state.last_sequence,
            "last_event_hash": state.last_event_hash,
            "format_version": state.format_version,
            "updated_at": state.updated_at,
            "evidence_log": str(self.evidence_path),
            "evidence_bytes": (
                self.evidence_path.stat().st_size if self.evidence_path.is_file() else 0
            ),
            "journal_present": self.journal_path.is_file(),
            "last_recovery": self.last_recovery.to_dict() if self.last_recovery else None,
        }

    def repair_from_log(self) -> NodeState:
        """Rebuild state from the evidence log's last complete record.

        The explicit administrative recovery path. Only ever moves state
        *forward* to what the log can actually prove; it never rewinds, because
        rewinding would reissue sequence numbers that signed records already use.
        """
        self._require_lock()
        tail = self._last_logged_record()
        try:
            state = self.read_state()
            current = state.last_sequence
        except (StateCorruptionError, EvidenceStateDivergence):
            current = 0
        if tail is None:
            if current:
                raise EvidenceStateDivergence(
                    f"cannot repair node {self.node_id!r}: state is at sequence {current} "
                    f"but {self.evidence_path} holds no complete records for it"
                )
            repaired = NodeState(node_id=self.node_id, key_id=self.key_id)
        else:
            repaired = NodeState(
                node_id=self.node_id,
                key_id=self.key_id,
                last_sequence=int(tail["sequence"]),
                last_event_hash=str(tail["event_hash"]),
                format_version=EVIDENCE_FORMAT_VERSION,
            )
        self._state = None
        self._write_state(repaired)
        return repaired


# ---------------------------------------------------------------------------
# Platform-specific advisory locking on a raw file descriptor
# ---------------------------------------------------------------------------


def _lock_exclusive(fd: int, timeout: float, path: Path) -> None:
    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        try:
            _try_lock(fd)
            return
        except BlockingIOError:
            pass
        except OSError as exc:  # pragma: no cover - unusual filesystems
            raise StateLockError(f"cannot lock {path}: {exc}") from exc
        if time.monotonic() >= deadline:
            raise StateLockError(
                f"timed out after {timeout}s waiting for the evidence lock {path}. "
                "Another signer holds it. Two signers must not share one node identity; "
                "if the previous signer crashed, confirm it is not running before "
                "removing the lock file."
            )
        time.sleep(0.02)


if _POSIX:

    def _try_lock(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        import fcntl

        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)

else:  # pragma: no cover - POSIX is the deployment target

    def _try_lock(fd: int) -> None:
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BlockingIOError(str(exc)) from exc

    def _unlock(fd: int) -> None:
        import msvcrt

        with contextlib.suppress(OSError):
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
