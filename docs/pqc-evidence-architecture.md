# PQC Evidence Architecture

## What this is, in one paragraph

`pqc_evidence` is a **post-quantum digital seal for honeypot logs**. Each node keeps a hash chain;
every event is wrapped in a versioned envelope carrying the previous event's hash, gets a SHA3-256
hash of its own, and is signed with an ML-DSA-65 private key that never leaves the node. Anyone
holding only the node's *public* key can then re-derive every hash and check every signature. The
result: if someone edits, deletes, reorders, duplicates or replays a recorded event, verification
says so — and says exactly which failure occurred.

## What it is not

| It is not | Because |
|---|---|
| TLS, or any secure channel | Transport security is a separate project. Nothing here encrypts a connection. |
| Encryption of Modbus/DNP3 traffic | The protocols stay exactly as they were. Only the *log* is sealed. |
| An attack prevention mechanism | It detects tampering with the record, after the fact. |
| Protection against wholesale deletion | An attacker who owns a node can delete its whole log. Selective edits are what become detectable. |
| Legal chain of custody | It is a tamper-evident *technical* mechanism. Evidentiary weight is a legal question this project makes no claim about. |

## Component map

```
                       events (dicts)
  honeypots ──────────────────────────────────▶ EventPublisher
  decoys                                             │
  controller                                         │ evidence sink attached?
  pcap tooling                                       │
                                          ┌──────────┴──────────┐
                                     no   │                     │  yes
                                          ▼                     ▼
                              runtime/events.jsonl        EvidenceSink
                              (unchanged behaviour)             │
                                                                ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │            EvidenceSigner  ──delegates persistence to──▶ EvidenceStore  │
   │                                                                         │
   │  EvidenceStore.append_signed() runs as ONE transaction under ONE lock:  │
   │    1. acquire       flock on runtime/pqc/<node>.lock (O_NOFOLLOW)       │
   │    2. recover       replay any journal left by an interrupted run       │
   │    3. allocate      next sequence + expected previous hash              │
   │    4. build+sign    canonical JSON → SHA3-256 → ML-DSA-65               │
   │    5. journal       write-ahead intent (seq, hash, offset, record)+fsync│
   │    6. append        write the record at that offset + fsync             │
   │    7. commit        atomic replace of state + fsync + dir fsync         │
   │    8. drop journal, release the lock                                    │
   └────────────────────────────────────┬───────────────────────────────────┘
                                        ▼
                          runtime/pqc/evidence.jsonl
                                        │
   ┌────────────────────────────────────┴───────────────────────────────────┐
   │  EvidenceCollector  ──▶  EvidenceVerifier  ──▶  KeyRegistry            │
   │  (chain-level:            (per-record:            (trusted public keys, │
   │   gaps, reorder,           hash, signature,        rotation, revocation,│
   │   duplicates, replay,      key status)             activation/expiry)   │
   │   chain resets)                                                         │
   └────────────────────────────────────┬───────────────────────────────────┘
                                        ▼
                     VerificationResult / StreamReport  (pqc_* alerts)
                                        │
                                        ▼
                       archive.py  (optional, offline)
             ML-KEM-768 → HKDF-SHA-256 → AES-256-GCM, manifest as AAD
```

## Module responsibilities

| Module | Responsibility |
|---|---|
| `models.py` | The versioned envelope and its strict validation. Every untrusted byte enters here. |
| `canonicalizer.py` | Deterministic JSON. Defines exactly which bytes get hashed and signed. |
| `event_chain.py` | SHA3-256 chain: genesis derivation, `event_hash`, chain cursor. |
| `crypto_backend.py` | Backend abstraction, runtime capability detection, backend registry. |
| `openssl_backend.py` | Native OpenSSL 3.5+ ML-DSA / ML-KEM. The preferred backend. |
| `key_registry.py` | Trusted public keys, lifecycle states, rotation, revocation, expiry. |
| `state_store.py` | The on-disk chain-position record and its atomic read/write primitives. |
| `evidence_store.py` | The transaction: lock, write-ahead journal, append, commit, recovery. |
| `signer.py` | Assembles and signs; delegates all persistence to `evidence_store`. |
| `verifier.py` | Per-record verification and the `pqc_*` alert vocabulary. |
| `collector.py` | Stream and archive verification; chain-level attack detection. |
| `archive.py` | Optional encrypted offline archives. |
| `benchmark.py` | Reproducible performance measurement. |
| `cli.py` | `ics-pqc-evidence`. |
| `integration.py` | The `EvidenceSink` that plugs into `EventPublisher`, plus `EvidenceMetrics`. |
| `common/publisher.py` | The factory every service calls to obtain a configured publisher. |

## Cryptographic choices, and why

**ML-DSA-65 (FIPS 204) for signatures.** A lattice-based scheme standardised by NIST in 2024,
at security category 3 — roughly AES-192. ICS deployments have very long lifetimes, and evidence
recorded today may need to remain verifiable well past the point where a cryptographically relevant
quantum computer would break ECDSA or RSA. Signatures are 3309 bytes and public keys 1952 bytes:
large by classical standards, which is why the storage overhead is measured and documented rather
than waved away.

**SHA3-256 (FIPS 202) for the chain.** Keccak-based, structurally different from SHA-2, and not
vulnerable to length-extension. Grover's algorithm reduces its preimage resistance to ~2^128, which
is ample.

**Signing over canonical JSON rather than raw bytes.** Two semantically identical events must
produce identical signed bytes, or a verifier that re-serialises would reject valid evidence. See
[pqc-evidence-format.md](pqc-evidence-format.md) for the canonicalization rules.

**KEM/DEM composition for archives.** ML-KEM-768 establishes a shared secret; HKDF-SHA-256 derives
an AES key; AES-256-GCM does the bulk encryption. ML-KEM is *never* used to encrypt data directly —
a KEM does not do that, and treating it as if it did is a classic misuse.

## Backend selection

Backends are selected by *capability at runtime*, never assumed:

1. **`openssl`** — preferred. Requires OpenSSL **3.5 or newer**; earlier releases do not implement
   ML-DSA at all, which the probe detects and reports precisely.
2. **`pyfips`** — pure-Python FIPS 204/203 (`dilithium-py`, `kyber-py`). Real post-quantum
   cryptography, not a mock, and byte-for-byte interoperable with OpenSSL: a signature made by one
   verifies under the other, which the test suite checks in both directions. Slower and not
   constant-time, so it is a portability and CI backend rather than the choice for a busy node.
3. **`insecure-test-only`** — a deterministic HMAC stand-in for unit tests. Never auto-selected,
   refuses to load when `ICS_PQC_PRODUCTION=1`, and stamps every key it emits with
   `INSECURE-TEST-ONLY-KEY-DO-NOT-USE`.

There is **no fallback to RSA, ECDSA, Ed25519 or HMAC**. If no post-quantum backend is available the
operation fails with a structured error naming what is missing and how to install it.

### Key formats

Public keys are exchanged as **raw algorithm bytes** (1952 bytes for ML-DSA-65), base64 encoded in
files and in the registry. That is the interoperable format, and the OpenSSL backend converts to and
from `SubjectPublicKeyInfo` DER on the way in and out.

Private keys are **not** interchangeable: OpenSSL stores a PKCS#8 PEM, the pure-Python backend uses
raw FIPS 204 bytes. The format is therefore detected from the key itself and the matching backend is
selected automatically. A private key never leaves its node, so this asymmetry costs nothing.

## Concurrency guarantees

`EvidenceStore` owns the lock, the journal, the log **and** the state, so allocation and append
cannot be separated. That yields three guarantees, each covered by a regression test:

| Guarantee | Enforced by |
|---|---|
| **File order is sequence order.** Record *n+1* never precedes record *n* in the file. | The append happens inside the same lock hold that allocated the sequence. |
| **A sequence number is used at most once.** | `flock` (`LOCK_EX`) on `runtime/pqc/<node>.lock`, opened `O_NOFOLLOW`, with a bounded timeout that raises `StateLockError` rather than blocking forever. |
| **No committed state without a durable record.** | Journal → append → commit, each `fsync`ed; the state file lands via `os.replace` plus a directory `fsync`. |

The earlier design allocated a sequence under the lock, released it, and let the caller append. Two
threads then reliably produced `[2, 1]` in the file. The regression test drives exactly that race —
sleeping only in the thread that receives sequence 1 — and asserts the file order.

Concurrency is enforced **across processes**, not merely across threads: the lock is an advisory
POSIX `flock`, so a second signer process on the same node identity waits until the timeout and then
fails loudly rather than interleaving. On Windows the store uses `msvcrt.locking` instead; POSIX is
the deployment target and is what the concurrency tests exercise.

Verification is stateless and parallelisable; the collector's per-node cursors are local to a run.

## Recovery from an interrupted transaction

Every `append_signed` first replays any journal left behind by a previous run. The journal records
the sequence, the event hash, the **byte offset** the record will occupy, and the record itself, so
recovery can always tell which side of the append a crash fell on:

| Journal state on disk | Action reported | Outcome |
|---|---|---|
| Record fully present at the offset | `completed_commit` | The crash was after the append. State is committed. Nothing is lost. |
| State already reflects the record | `already_committed` | The crash was after the commit, before the journal was dropped. No-op. |
| Record absent or partially written | `rolled_back_partial_append` | Truncate to the recorded offset, first copying the discarded bytes to `evidence.jsonl.partial-<epoch>` (mode 0600) beside the log. The sequence is reused — safe, because no complete signed record ever claimed it. |
| Journal unparsable | `discarded_unreadable_journal` | Preserved and discarded; the log is authoritative. |
| Journal belongs to another node | `discarded_foreign_journal` | Preserved and discarded; never applied to this chain. |

A `RecoveryReport` is returned to the caller and kept as `EvidenceStore.last_recovery`;
`ics-pqc-evidence status` reports whether a journal is pending, and
`EvidenceMetrics.state_recoveries` counts recoveries, so a recovery is visible rather than hidden.

**What recovery deliberately will not do.** If committed state is *ahead* of the log — state says
sequence 40, the log ends at 30 — signed records were lost after being committed. That is not
repairable from inside: the records are gone. Recovery stops with `EvidenceStateDivergence`, and the
only way forward is an explicit operator decision:

```bash
ics-pqc-evidence recover-state --node-id rpi-01 --key-id rpi-01-k1 \
    --private-key runtime/pqc/rpi-01.key --confirm
```

That command rebuilds state from the log's last complete record and refuses to run without
`--confirm`. It only ever moves state *forward* to what the log can prove; it never rewinds, because
rewinding would reissue sequence numbers that existing signed records already use. Silently
continuing would either reuse sequence numbers or paper over evidence loss.

## Performance

Measured on this development machine (WSL2, x86-64) with the pure-Python backend, which is the
*slow* path:

| Operation | Mean |
|---|---|
| ML-DSA-65 keygen | ~7 ms |
| ML-DSA-65 sign | ~30–50 ms |
| ML-DSA-65 verify | ~7 ms |
| ML-KEM-768 encapsulate | ~3 ms |
| Signed record size | ~4.9 KB (vs ~120 B unsigned) |

Signing latency has high variance because ML-DSA uses rejection sampling — the number of attempts
varies per signature. That is inherent to the algorithm, not a defect. The native OpenSSL backend is
substantially faster. Run `ics-pqc-evidence benchmark` on your own hardware; see
[pqc-benchmarks.md](pqc-benchmarks.md).

The storage cost is the real design consideration: signing every event multiplies log size by roughly
40×. For a Raspberry Pi node, sign the events that matter (`sabotage_detected`, `login_attempt`)
rather than every `modbus_request`, or sign in batches offline with `ics-pqc-evidence sign-log`.

## Integration modes

| Mode | Raw event log | Signed evidence log |
|---|---|---|
| `disabled` (default) | written | — |
| `sign` | — | written |
| `dual` | written | written |
| `verify-only` | written | — (verifies externally produced evidence) |

Nothing is signed unless an operator explicitly configures a key and a mode. **No signing key is
ever created implicitly** — not on first start, not by the deployment script.
