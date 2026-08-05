"""The SHA3-256 tamper-evident event chain.

Each node maintains its own chain. Event *n* carries the ``event_hash`` of
event *n-1*, so changing any earlier event invalidates every later hash — the
same construction as a hash chain in an append-only log.

Genesis
-------
The first event of a chain has no predecessor. Using a null, empty or all-zero
previous hash would be ambiguous: an attacker could truncate a chain to a single
event and claim it was always the first, and two different nodes would produce
interchangeable genesis records.

Instead the genesis previous-hash is **derived and node-bound**::

    previous_event_hash = SHA3-256("ics-deception/pqc-evidence/genesis/v1/" + node_id)

That value is deterministic (a verifier can recompute it), unique per node (a
genesis record cannot be moved between chains), and distinguishable from a real
event hash only by recomputation — which is exactly what the verifier does.

Chain rules enforced here:

* ``sequence`` starts at 1 and increases by exactly 1.
* ``previous_event_hash`` of event *n* equals ``event_hash`` of event *n-1*.
* ``event_hash`` is SHA3-256 over the canonical envelope excluding
  ``event_hash`` and ``signature``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ics_deception.pqc_evidence.models import SignedEvent

__all__ = [
    "GENESIS_DOMAIN",
    "ChainPosition",
    "compute_event_hash",
    "expected_previous_hash",
    "genesis_previous_hash",
    "is_genesis",
    "verify_event_hash",
]

#: Domain-separation prefix for genesis previous-hash derivation. Changing this
#: changes every chain's genesis value, so it is versioned in the string itself.
GENESIS_DOMAIN = b"ics-deception/pqc-evidence/genesis/v1/"

#: The first sequence number of every chain.
FIRST_SEQUENCE = 1


def genesis_previous_hash(node_id: str) -> str:
    """Return the deterministic, node-bound genesis previous-hash."""
    digest = hashlib.sha3_256(GENESIS_DOMAIN + node_id.encode("utf-8")).hexdigest()
    return digest


def is_genesis(event: SignedEvent) -> bool:
    """Return whether ``event`` claims to be the first event of its chain."""
    return event.sequence == FIRST_SEQUENCE


def expected_previous_hash(node_id: str, sequence: int, last_event_hash: str | None) -> str:
    """Return the ``previous_event_hash`` an event at ``sequence`` must carry.

    ``last_event_hash`` is the previous event's hash, or ``None`` at genesis.
    """
    if sequence == FIRST_SEQUENCE:
        return genesis_previous_hash(node_id)
    if last_event_hash is None:
        raise ValueError(f"sequence {sequence} requires a previous event hash")
    return last_event_hash


def compute_event_hash(event: SignedEvent) -> str:
    """Compute the SHA3-256 ``event_hash`` for an envelope.

    Hashes the canonical form of the envelope **excluding** ``event_hash`` and
    ``signature``, so the value is independent of both.
    """
    return hashlib.sha3_256(event.hash_payload()).hexdigest()


def verify_event_hash(event: SignedEvent) -> bool:
    """Return whether the stored ``event_hash`` matches the recomputed one."""
    import hmac

    # Constant-time comparison is not strictly required for a public hash, but
    # it costs nothing and keeps every digest comparison in this package uniform.
    return hmac.compare_digest(compute_event_hash(event), event.event_hash)


@dataclass
class ChainPosition:
    """Mutable cursor tracking one node's chain while signing or verifying.

    Not thread-safe on its own; the signer serialises access through the state
    store's file lock.
    """

    node_id: str
    last_sequence: int = 0
    last_event_hash: str | None = None

    @property
    def next_sequence(self) -> int:
        """The sequence number the next event must carry."""
        return self.last_sequence + 1

    def previous_hash_for_next(self) -> str:
        """The ``previous_event_hash`` the next event must carry."""
        return expected_previous_hash(self.node_id, self.next_sequence, self.last_event_hash)

    def advance(self, event: SignedEvent, event_hash: str | None = None) -> None:
        """Record that ``event`` has been committed to the chain.

        ``event_hash`` overrides the value stored in the record. Verifiers pass
        the **recomputed** hash so that a tampered record cannot dictate what
        the next record must link to: the following event is then checked
        against reality, not against the forger's claim.
        """
        self.last_sequence = event.sequence
        self.last_event_hash = event_hash if event_hash is not None else event.event_hash

    def to_dict(self) -> dict[str, Any]:
        """Return a serialisable snapshot."""
        return {
            "node_id": self.node_id,
            "last_sequence": self.last_sequence,
            "last_event_hash": self.last_event_hash,
        }
