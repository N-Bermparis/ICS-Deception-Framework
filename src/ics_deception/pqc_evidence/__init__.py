"""``pqc_evidence`` — a post-quantum digital seal for honeypot logs.

In one sentence: it helps prove that a recorded event really came from a
trusted honeypot node and was not secretly changed, deleted, reordered or
replayed afterwards.

How it works
------------
Each node keeps a hash chain. Every event is wrapped in a versioned envelope
that carries the previous event's hash, gets a SHA3-256 ``event_hash`` of its
own, and is signed with an ML-DSA-65 (FIPS 204) private key that never leaves
the node. A verifier with only the node's *public* key can then re-derive every
hash and check every signature, so any modification, deletion, reordering,
duplication or replay shows up as a specific, named failure.

What it is **not**
------------------
* It is **not TLS** and not any kind of secure channel. Transport security is a
  separate concern maintained as a separate project.
* It does **not** encrypt Modbus or DNP3 traffic.
* It does **not** prevent attacks; it makes tampering with the *record* of an
  attack detectable.
* It does **not** stop an attacker who fully compromises a node from deleting
  that node's entire log — it only makes selective edits detectable.
* It does **not** guarantee legal chain of custody. It is a tamper-evident
  technical mechanism, nothing more.

Everything here is optional and **disabled by default**: with no configuration,
the framework keeps writing plain unsigned JSONL exactly as before.
"""

from __future__ import annotations

__all__ = [
    "DEFAULT_HASH_ALGORITHM",
    "DEFAULT_SIGNATURE_ALGORITHM",
    "EVIDENCE_FORMAT_VERSION",
    "EvidenceError",
    "EvidenceMode",
]

#: Version of the signed-event envelope produced by this package.
EVIDENCE_FORMAT_VERSION = "1.0"

#: Default post-quantum signature algorithm (FIPS 204, security category 3).
DEFAULT_SIGNATURE_ALGORITHM = "ML-DSA-65"

#: Default hash algorithm for the event chain (FIPS 202).
DEFAULT_HASH_ALGORITHM = "SHA3-256"


class EvidenceError(Exception):
    """Base class for every error raised by :mod:`ics_deception.pqc_evidence`."""


class EvidenceMode:
    """Publisher integration modes.

    ``disabled``
        Preserve the current unsigned JSONL behaviour. This is the default.
    ``sign``
        Write signed evidence envelopes only.
    ``dual``
        Write both the raw event and the signed envelope, for migration and
        side-by-side comparison.
    ``verify_only``
        Do not sign; verify externally created signed evidence.
    """

    DISABLED = "disabled"
    SIGN = "sign"
    DUAL = "dual"
    VERIFY_ONLY = "verify-only"

    ALL = (DISABLED, SIGN, DUAL, VERIFY_ONLY)
