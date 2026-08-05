"""Evidence signer: turn plain events into durably persisted chain records.

Signing one event is a single transaction owned by
:class:`~ics_deception.pqc_evidence.evidence_store.EvidenceStore`:

1. Take the node's exclusive lock (bounded timeout).
2. Recover any interrupted transaction.
3. Allocate ``sequence = last_sequence + 1`` and the previous hash.
4. Canonicalize the unsigned envelope and compute ``event_hash`` (SHA3-256).
5. Sign the canonical envelope *including* ``event_hash`` (ML-DSA).
6. Write the write-ahead journal and ``fsync`` it.
7. Append the record to the evidence log and ``fsync`` it.
8. Commit state atomically.
9. Drop the journal, release the lock.

Steps 3 to 8 all happen **inside the lock**, which is what makes the physical
order of the evidence file identical to sequence order. An earlier design
allocated under the lock and let the caller append afterwards; two threads then
reliably wrote ``sequence 2`` before ``sequence 1``.

The signer no longer returns a record for the caller to persist — persistence is
part of signing. That removes the whole class of "signed but never written" and
"written twice" bugs by construction.
"""

from __future__ import annotations

import base64
import contextlib
import os
import stat
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import (
    DEFAULT_HASH_ALGORITHM,
    DEFAULT_SIGNATURE_ALGORITHM,
    EvidenceError,
)
from ics_deception.pqc_evidence.crypto_backend import (
    TEST_KEY_MARKER,
    BackendError,
    CryptoBackend,
    KeyPair,
    select_backend,
)
from ics_deception.pqc_evidence.event_chain import compute_event_hash
from ics_deception.pqc_evidence.evidence_store import EvidenceStore
from ics_deception.pqc_evidence.models import SignedEvent

__all__ = [
    "EvidenceSigner",
    "SignerError",
    "SigningReport",
    "load_private_key",
    "write_private_key",
]


class SignerError(EvidenceError):
    """Signing failed."""


def write_private_key(path: str | Path, key: KeyPair) -> Path:
    """Write a private key with 0600 permissions, refusing to clobber.

    Created with ``O_EXCL`` so an existing key is never silently overwritten:
    losing a signing key means losing the ability to continue that chain.
    """
    key_path = Path(path).expanduser()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SignerError(
            f"refusing to overwrite the existing private key {key_path}; "
            "move it aside deliberately if you really mean to replace it"
        ) from exc
    except OSError as exc:
        raise SignerError(f"cannot create private key {key_path}: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key.private_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise SignerError(f"cannot write private key {key_path}: {exc}") from exc
    os.chmod(key_path, 0o600)
    return key_path


def load_private_key(path: str | Path, require_strict_permissions: bool = True) -> bytes:
    """Read a private key, refusing one that others can read."""
    key_path = Path(path).expanduser()
    if not key_path.is_file():
        raise SignerError(f"private key not found: {key_path}")
    if require_strict_permissions and os.name != "nt":
        mode = key_path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SignerError(
                f"private key {key_path} is group/world accessible (mode "
                f"{stat.S_IMODE(mode):04o}); fix with: chmod 600 {key_path}"
            )
    data = key_path.read_bytes()
    if not data:
        raise SignerError(f"private key {key_path} is empty")
    return data


@dataclass
class SigningReport:
    """Summary of a batch signing run."""

    signed: int = 0
    skipped: int = 0
    errors: int = 0
    first_sequence: int | None = None
    last_sequence: int | None = None
    node_id: str = ""
    key_id: str = ""
    backend: str = ""
    real_pqc: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable report."""
        return {
            "signed": self.signed,
            "skipped": self.skipped,
            "errors": self.errors,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "node_id": self.node_id,
            "key_id": self.key_id,
            "backend": self.backend,
            "real_pqc": self.real_pqc,
        }


class EvidenceSigner:
    """Signs events into a node's tamper-evident, durably ordered chain.

    Parameters
    ----------
    node_id, key_id:
        Identity written into every envelope.
    private_key:
        Raw private key bytes (PEM for the OpenSSL backend, raw for pyfips).
    state_path:
        Where the chain position, lock and journal live.
    evidence_path:
        The evidence log. Defaults to ``evidence.jsonl`` beside the state file.
    backend:
        An explicit backend, or ``None`` to select one that can consume this
        key's format.
    """

    def __init__(
        self,
        node_id: str,
        key_id: str,
        private_key: bytes,
        state_path: str | Path,
        evidence_path: str | Path | None = None,
        backend: CryptoBackend | None = None,
        algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
        hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
        lock_timeout: float = 10.0,
    ) -> None:
        if not private_key:
            raise SignerError("private key must not be empty")
        if lock_timeout <= 0:
            raise SignerError("lock_timeout must be greater than zero")
        self.node_id = node_id
        self.key_id = key_id
        self.algorithm = algorithm
        self.hash_algorithm = hash_algorithm
        self.state_path = Path(state_path).expanduser()
        self.evidence_path = (
            Path(evidence_path).expanduser()
            if evidence_path is not None
            else self.state_path.with_name("evidence.jsonl")
        )
        self.lock_timeout = lock_timeout
        self._private_key = private_key
        # Without an explicit backend, pick the one that owns this key's format:
        # an OpenSSL PEM and a raw FIPS 204 key are not interchangeable.
        self._backend = (
            backend
            if backend is not None
            else select_backend(algorithm=algorithm, for_private_key=private_key)
        )

        capabilities = self._backend.capabilities()
        self.real_pqc = capabilities.real_pqc
        if private_key.startswith(TEST_KEY_MARKER) and capabilities.real_pqc:
            raise SignerError(
                "this private key is marked INSECURE-TEST-ONLY but a real cryptographic "
                "backend was selected; refusing to produce evidence that looks genuine"
            )

    @property
    def backend_name(self) -> str:
        """Name of the backend performing the signatures."""
        return self._backend.name

    def store(self) -> EvidenceStore:
        """Return an unlocked store for this signer's node."""
        return EvidenceStore(
            state_path=self.state_path,
            evidence_path=self.evidence_path,
            node_id=self.node_id,
            key_id=self.key_id,
            lock_timeout=self.lock_timeout,
        )

    def status(self) -> dict[str, Any]:
        """Return chain status. Contains no key material."""
        with self.store() as store:
            snapshot = store.status()
        snapshot.update(
            {
                "backend": self.backend_name,
                "real_pqc": self.real_pqc,
                "algorithm": self.algorithm,
            }
        )
        return snapshot

    # -- one event ---------------------------------------------------------

    def sign_event(
        self,
        event: dict[str, Any],
        timestamp: str | None = None,
        fault: Callable[[str], None] | None = None,
    ) -> SignedEvent:
        """Sign one event and persist it durably, in order.

        The returned record is already written to the evidence log; callers must
        not append it again.

        ``fault`` is a test-only hook fired at each transaction stage.
        """
        moment = timestamp or datetime.now(timezone.utc).isoformat()
        with self.store() as store:
            return self._transact(store, event, moment, fault)

    def _transact(
        self,
        store: EvidenceStore,
        event: dict[str, Any],
        timestamp: str,
        fault: Callable[[str], None] | None = None,
    ) -> SignedEvent:
        produced: dict[str, SignedEvent] = {}

        def build_and_sign(sequence: int, previous_hash: str) -> tuple[str, str]:
            record = self._build_and_sign(event, timestamp, sequence, previous_hash)
            produced["record"] = record
            return record.to_json_line(), record.event_hash

        store.append_signed(build_and_sign, key_id=self.key_id, fault=fault)
        return produced["record"]

    def _build_and_sign(
        self, event: dict[str, Any], timestamp: str, sequence: int, previous_hash: str
    ) -> SignedEvent:
        envelope = SignedEvent.build_unsigned(
            node_id=self.node_id,
            sequence=sequence,
            timestamp=timestamp,
            previous_event_hash=previous_hash,
            event=event,
            key_id=self.key_id,
            signature_algorithm=self.algorithm,
            hash_algorithm=self.hash_algorithm,
        )
        envelope = envelope.with_event_hash(compute_event_hash(envelope))
        try:
            raw_signature = self._backend.sign(
                self._private_key, envelope.signing_payload(), self.algorithm
            )
        except BackendError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise SignerError(f"signing failed: {exc}") from exc
        if not raw_signature:
            raise SignerError("backend returned an empty signature")
        return envelope.with_signature(
            base64.b64encode(raw_signature).decode("ascii"), raw_signature
        )

    # -- batches -----------------------------------------------------------

    def sign_events(
        self, events: Iterable[dict[str, Any]]
    ) -> Iterator[SignedEvent]:
        """Sign many events under a single lock acquisition.

        Each event is still its own transaction — journal, append, commit — so a
        crash mid-batch leaves a consistent chain. Holding the lock across the
        batch just avoids re-acquiring it per event.
        """
        with self.store() as store:
            for event in events:
                moment = datetime.now(timezone.utc).isoformat()
                yield self._transact(store, event, moment)

    def sign_log(
        self,
        source: Iterable[str],
        max_events: int | None = None,
    ) -> SigningReport:
        """Sign every JSON line from ``source`` into this signer's evidence log.

        Blank lines are skipped. A line that is not a JSON object is counted as
        an error and skipped, so one corrupt line does not lose the rest.
        """
        import json

        report = SigningReport(
            node_id=self.node_id,
            key_id=self.key_id,
            backend=self.backend_name,
            real_pqc=self.real_pqc,
        )

        def _events() -> Iterator[dict[str, Any]]:
            count = 0
            for line in source:
                text = line.strip()
                if not text:
                    report.skipped += 1
                    continue
                if max_events is not None and count >= max_events:
                    break
                try:
                    parsed = json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    report.errors += 1
                    continue
                if not isinstance(parsed, dict):
                    report.errors += 1
                    continue
                count += 1
                yield parsed

        for record in self.sign_events(_events()):
            report.signed += 1
            if report.first_sequence is None:
                report.first_sequence = record.sequence
            report.last_sequence = record.sequence
        return report

    # -- administrative ----------------------------------------------------

    def repair_state_from_log(self) -> dict[str, Any]:
        """Rebuild chain state from the evidence log. Explicit operator action."""
        store = self.store()
        store.acquire()
        try:
            with contextlib.suppress(Exception):
                store.recover()
            repaired = store.repair_from_log()
            return repaired.to_dict()
        finally:
            store.release()
