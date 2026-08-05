# PQC Evidence Threat Model

Scope: the `pqc_evidence` layer only. The framework-wide model is in
[threat-model.md](threat-model.md) and still applies.

## The question this layer answers

> Given a JSONL file claiming to be a honeypot's event log, can I tell whether it is what that
> honeypot actually recorded?

Not "is the honeypot secure", not "was the attack prevented". Just: **is this record intact, and did
it come from a node I trust?**

## Assets

| # | Asset | Why it matters |
|---|---|---|
| E1 | Integrity of recorded events | The whole point. A silently edited log is worse than no log — it misleads. |
| E2 | Node signing private key | Whoever holds it can forge evidence indistinguishable from real. |
| E3 | Trusted-key registry | If an attacker can add a key, they can mint trusted evidence. |
| E4 | Chain state file | Corrupt or rewind it and sequence numbers can be reused, breaking uniqueness. |
| E5 | Archive KEM private key | Decrypts every archive sealed to it. |
| E6 | The verifier's verdict | A verifier that says "valid" when it should not is the worst failure here. |

## Adversaries

| ID | Adversary | Capability |
|---|---|---|
| P1 | Remote attacker interacting with the honeypot | Sends arbitrary bytes; controls event *content* but not the signing |
| P2 | Attacker who compromises a node | Root on the node: can read the private key, stop the service, delete the log |
| P3 | Insider with log storage access | Can modify or delete stored evidence files, but has no signing key |
| P4 | Malicious evidence supplier | Hands you a crafted "evidence" file to analyse |
| P5 | Future quantum adversary | Can break ECDSA/RSA; the reason ML-DSA is used |

## Threats and outcomes

### Against the record (E1)

| ID | Threat | Adversary | Detected? | How |
|---|---|---|---|---|
| PE-01 | Edit an event body | P3 | **Yes** | `pqc_event_hash_mismatch` + `pqc_invalid_signature` |
| PE-02 | Edit a timestamp | P3 | **Yes** | Timestamp is inside the hash and the signature |
| PE-03 | Delete an event | P3 | **Yes** | `pqc_sequence_gap` + `pqc_previous_hash_mismatch` |
| PE-04 | Reorder events | P3 | **Yes** | Chain linkage does not match |
| PE-05 | Duplicate an event | P3 | **Yes** | `pqc_replayed_event` |
| PE-06 | Replay an old event into a new position | P3 | **Yes** | `event_hash` seen before at a different sequence |
| PE-07 | Two events at one sequence (fork) | P3 | **Yes** | `pqc_duplicate_sequence` |
| PE-08 | Splice events from another node's chain | P3 | **Yes** | Genesis is node-bound; `node_id` is signed |
| PE-09 | Substitute a signature from another record | P3 | **Yes** | Signature covers `event_hash` and `sequence` |
| PE-10 | Truncate the log at the end | P3 | **No** (see below) | — |
| PE-11 | Delete the entire log | P2, P3 | **No** (see below) | — |

### Against the keys (E2, E3)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| PE-12 | Steal a node's private key | Key never leaves the node; mode `0600`; excluded from deployment sync, backups and archives; refuses to load if group/world readable | **High for P2.** Root on the node reads the key. Unavoidable — mitigate by rotation and revocation. |
| PE-13 | Forge evidence with a stolen key | Revocation marks every signature from that key untrusted | Medium — depends on noticing the compromise |
| PE-14 | Add an attacker key to the registry | Registry is a separate, operator-controlled file; not writable by the node; duplicate/conflicting entries rejected | Medium — whoever writes the registry is trusted by definition |
| PE-15 | Use a key before activation or after expiry | Activation and expiry checked against the *event timestamp* | Low |
| PE-16 | Downgrade to a weak algorithm | Only ML-DSA identifiers accepted; no RSA/ECDSA/Ed25519/HMAC path exists | Low |
| PE-17 | Trick the verifier into the test backend | Never auto-selected; requires an explicit flag; refuses under `ICS_PQC_PRODUCTION=1`; test keys carry a marker and the signer refuses to mix them with a real backend | Low |

### Against the chain state (E4)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| PE-18 | Reuse a sequence number after a crash | Write-ahead journal names the sequence and the byte offset. Recovery commits a fully written record, or rolls back a partial one and reuses the sequence — which is safe precisely because no complete signed record ever claimed it | Low |
| PE-19 | Two signers sharing one node identity | Exclusive `flock` held across allocate–sign–append–commit, not merely across the state read-modify-write. Bounded timeout, so a stuck holder fails loudly rather than hanging | Low |
| PE-20 | Corrupt or truncated state | Every field validated; corruption raises rather than being silently repaired | Low — requires operator recovery, which is the correct outcome |
| PE-21 | Rewind state to re-sign a sequence | `repair_from_log` only ever moves state forward to what the log proves, and requires `--confirm` | Low |
| PE-22 | Delete state to restart the chain | Not prevented, but **visible**: `pqc_chain_reset` | Accepted |
| PE-38 | Write records out of order to confuse a reader that trusts file order | Append happens inside the lock hold that allocated the sequence, so file order *is* sequence order | Low |
| PE-39 | Interrupt a signer mid-append to leave a half-written record that a verifier treats as corruption | Partial record is truncated back to the journalled offset and preserved as `evidence.jsonl.partial-<epoch>` (0600) for inspection | Low |
| PE-40 | Truncate the log after state was committed, then let the node continue and hope the loss is silent | Detected as `EvidenceStateDivergence`; signing stops until an operator runs `recover-state --confirm`, and the gap remains visible as `pqc_sequence_gap` | Medium — the lost records are unrecoverable by design |

### Against the verifier (E6, P4)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| PE-23 | Crash the verifier with crafted input | Every parse failure becomes a structured error; size limits before parsing; depth limits; hostile-input tests | Low |
| PE-24 | Memory exhaustion via a huge record | 256 KiB per record, checked before JSON decoding | Low |
| PE-25 | Duplicate JSON keys to desync reader and verifier | Duplicate keys rejected outright | Low |
| PE-26 | `NaN`/`Infinity` to break comparisons | Rejected at parse time | Low |
| PE-27 | Unicode tricks | Strict UTF-8; lone surrogates rejected | Low |
| PE-28 | Unsigned data in an unknown field | Unknown envelope fields rejected | Low |
| PE-29 | Replay-detection memory growth | Tracked hashes capped; the cap being hit is itself reported | Low |

### Against archives (E5)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| PE-30 | Modify ciphertext | AES-256-GCM authentication fails | Low |
| PE-31 | Substitute manifest fields | The **entire** manifest is the AEAD's additional authenticated data; the GCM tag is no longer a manifest field that could be rewritten alongside it | Low |
| PE-32 | Wrong ML-KEM private key | Implicit rejection yields a wrong secret → GCM auth failure | Low |
| PE-33 | Truncated archive | Declared ciphertext length checked; container validated | Low |
| PE-34 | Path traversal on extraction | Nothing is extracted to a path; entry names validated anyway | Low |
| PE-35 | Decompression bomb | Ciphertext is authenticated **before** any byte reaches the decompressor, then inflated in bounded chunks against a hard output cap | Low |
| PE-36 | Extra or duplicate entries | Exactly two expected entries; anything else rejected | Low |
| PE-37 | Pass off an archive as verified when only the container was checked | `ArchiveTrust` reports six independent facts; `fully_verified` requires all six, and authenticating without a key registry warns that the enclosed evidence was **not** verified | Low |

## What this layer does **not** protect against

State these plainly, because a security control that is oversold is worse than none.

**1. Wholesale deletion (PE-11).** An attacker with root on a node can delete the log and the state
file. Signing makes *selective editing* detectable; it cannot make bytes survive an `rm`. Mitigate
by shipping evidence off the node continuously — a deleted local copy then contradicts the remote
one, which is itself a signal.

**2. Truncation at the end (PE-10).** A verifier reading a file ending at sequence 40 cannot know
whether the node ever wrote 41. There is no "final" marker, and there cannot be one for a live log.
Mitigate by recording the highest sequence seen elsewhere, or by periodically publishing the current
chain head somewhere the attacker does not control.

**3. Forgery with a stolen key (PE-13).** ML-DSA is only as good as the secrecy of the private key.
On a honeypot — a machine you *expect* to be compromised — this is the dominant residual risk.
Rotation limits the window; revocation limits the damage; neither prevents it.

**4. Lies at the source.** If the honeypot records an event incorrectly, the signature faithfully
attests to an incorrect event. Signing proves *provenance and integrity*, never *truth*.

**5. Timestamp accuracy.** The timestamp is whatever the node's clock said. A node with a wrong or
manipulated clock produces correctly-signed events with wrong times. Use NTP; treat timestamps as
claims by the node, not facts.

**6. Legal chain of custody.** This is a tamper-evident technical mechanism. Whether it satisfies an
evidentiary standard in a jurisdiction is a legal question, and **no claim is made here**.

**7. Confidentiality of the event log.** Signing does not encrypt. The evidence log is plaintext and
contains attacker-supplied content. Archives are the optional confidentiality mechanism.

**8. Any transport security whatsoever.** This is not TLS. Modbus and DNP3 traffic is untouched.

**9. The unsigned window on native C++ events.** The Python services sign each event before
`publish()` returns, so an event is durable and sealed essentially at the moment it occurs. The
native `modbus_honeypot`, `fake_telnet` and `fake_ssh` binaries contain no cryptographic code: they
write plain JSONL and are sealed afterwards with `sign-log`. Between an event being written and that
batch running, an attacker with write access to `runtime/` can alter it and the signature will
faithfully attest to the altered version. Shorten the interval, or move the capture to the Python
path, if that window matters for your experiment.

**10. Loss of already-committed evidence.** The transaction guarantees no committed state without a
durable record. It cannot guarantee the reverse: if the log is destroyed after records were
committed, they are gone. Recovery deliberately refuses to invent replacements, and the resulting
gap stays visible as `pqc_sequence_gap`.

## The post-quantum rationale

ICS deployments run for decades and evidence may be examined years after collection. An adversary
who records signed evidence today and gains a cryptographically relevant quantum computer later
could, with a classical scheme, forge signatures that appear to date from today. ML-DSA-65 is a
NIST-standardised lattice scheme (FIPS 204, security category 3) chosen so that the *verifiability*
of evidence outlives the classical assumptions.

Honest caveats:

* Lattice cryptography is younger than RSA and ECC. Standardisation reduces risk; it does not
  eliminate it.
* The pure-Python backend is **not constant-time**. Signing is a local operation with no remote
  timing oracle in this design, but on a shared host prefer the native OpenSSL backend.
* ML-DSA-65 signatures are 3309 bytes. The storage cost is real, measured, and documented — not
  hidden.

## Assumptions

Everything above rests on:

1. The signing private key is secret at the moment of signing.
2. The registry reflects the operator's actual trust decisions.
3. The verifier runs on a machine the attacker does not control.
4. SHA3-256 is collision resistant and ML-DSA-65 is unforgeable.
5. The node's clock is roughly correct.

If (1) or (3) fails, the guarantees do not hold. That is not a weakness of the design; it is the
boundary of what any signing scheme can offer, stated where it can be read.
