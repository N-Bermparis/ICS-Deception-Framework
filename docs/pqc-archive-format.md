# Encrypted Evidence Archive Format, version 2.0

Optional, offline confidentiality for a body of already-signed evidence. Entirely separate from
routine event signing: you can sign forever and never make an archive.

## Cryptographic construction

```
  ML-KEM-768   (FIPS 203)   encapsulate to recipient  →  shared secret (32 B) + ciphertext (1088 B)
  HKDF-SHA-256 (RFC 5869)   salt = random 32 B, info = "ics-deception/pqc-evidence/archive/v2"
                                                      →  AES-256 key (32 B)
  zlib                      compress the evidence, streamed in 1 MiB chunks
  AES-256-GCM               nonce = random 12 B, AAD = the manifest
                                                      →  ciphertext ‖ 16 B tag
```

Everything after key establishment is **streamed** in `CHUNK_BYTES` (1 MiB) units: the plaintext is
hashed, compressed and encrypted chunk by chunk, and never held whole in memory. See
[Memory behaviour](#memory-behaviour).

**ML-KEM never encrypts the evidence directly.** A KEM establishes a shared secret; a symmetric AEAD
does the bulk encryption. That is KEM/DEM composition, and using a KEM as if it were public-key
encryption is a classic misuse this format deliberately avoids.

## Container

A ZIP with **exactly two stored (uncompressed) entries**:

```
evidence.pqcarch
├── manifest.json     plaintext metadata, integrity-protected as AEAD additional data
└── evidence.bin      AES-256-GCM ciphertext followed by the 16-byte tag
```

The GCM tag lives **only** at the end of `evidence.bin`, never in the manifest. Version 1.0 carried
an `auth_tag` manifest field and then had to exclude that one field from its own AAD — a fragile
special case, and a value an attacker could rewrite in the clear. In 2.0 the manifest is
authenticated in full and the tag is exactly where the AEAD output puts it.

Ciphertext is incompressible, so `ZIP_STORED` avoids wasted effort and removes any zip-level
decompression-bomb surface. The gzip layer sits *inside* the encryption, where it can be bounded on
read.

## Manifest

```json
{
  "archive_format_version": "2.0",
  "node_id": "rpi-honeypot-01",
  "key_id": "rpi-honeypot-01-2026-01",
  "first_sequence": 1,
  "last_sequence": 154,
  "event_count": 154,
  "created_at": "2026-08-05T18:20:00.000000Z",
  "chain_final_hash": "<64 hex: event_hash of the last record>",
  "plaintext_sha3_256": "<64 hex: digest of the plaintext evidence>",
  "plaintext_length": 754321,
  "kem_algorithm": "ML-KEM-768",
  "kdf_algorithm": "HKDF-SHA-256",
  "aead_algorithm": "AES-256-GCM",
  "encapsulated_key": "<base64, 1088 bytes>",
  "hkdf_salt": "<base64, 32 bytes>",
  "nonce": "<base64, 12 bytes>",
  "ciphertext_length": 123456,
  "metadata": {}
}
```

### Manifest binding

The manifest is stored in the clear but is **not** unprotected: its **entire** canonical JSON is
passed to AES-GCM as **additional authenticated data**. Changing `node_id`, a sequence range, an
algorithm identifier or the plaintext digest makes decryption fail with an authentication error
rather than silently producing evidence attributed to the wrong node.

This is why substitution attacks on the manifest are detected without a second signature.

## Creating an archive

```bash
ics-pqc-evidence create-archive --input runtime/pqc/evidence.jsonl --output archives/2026-08-05.pqcarch --recipient-public-key keys/archive.pub --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01
```

The recipient's ML-KEM-768 **public** key is all that is needed. The archive is written atomically
and chmod'ed `0600`.

## What verification actually proves

The single most important thing to understand about this format: **decrypting an archive
successfully tells you nothing about whether the evidence inside is sound.** Those are separate
questions with separate keys, and conflating them is how an operator ends up trusting forged events
because "the archive opened fine".

`ArchiveTrust` therefore reports six **independent** facts. None implies another, and
`fully_verified` is true only when all six hold — it is never inferred from a subset.

| Fact | What it proves | Requires |
|---|---|---|
| `container_authenticated` | The ciphertext and the manifest bound to it are intact and were sealed to this recipient. | ML-KEM private key |
| `plaintext_hash_verified` | The recovered plaintext matches `plaintext_sha3_256` and `plaintext_length`. | ML-KEM private key |
| `evidence_format_valid` | Every line inside is a well-formed evidence record of a supported version. | ML-KEM private key |
| `evidence_signatures_verified` | Every enclosed record carries a valid ML-DSA signature from a trusted key. | registry of public keys |
| `evidence_chain_verified` | The enclosed records form an unbroken hash chain with no gaps, reorders or duplicates. | registry of public keys |
| `node_identity_verified` | The `node_id`/`key_id` the manifest claims match what the enclosed records actually say. | registry of public keys |

The last three are the ones an archive **cannot** answer by itself. Whoever built the archive chose
its manifest; only the node's public signing key can contradict it.

### Three levels of checking

```bash
# 1. Container structure only. No keys. Detects truncation, tampering with the
#    entry list, unsupported algorithms. Reports "not_authenticated".
ics-pqc-evidence verify-archive --input archives/2026-08-05.pqcarch

# 2. + cryptographic authentication of the container and its manifest.
ics-pqc-evidence verify-archive --input archives/2026-08-05.pqcarch     --recipient-private-key keys/archive.key

# 3. + verification of the signed evidence inside. This is the only level that
#    can report fully_verified.
ics-pqc-evidence verify-archive --input archives/2026-08-05.pqcarch     --recipient-private-key keys/archive.key --registry keys/registry.json
```

Level 2 without a registry emits an explicit warning that the enclosed evidence was **not** verified,
so a passing exit code at level 2 cannot be mistaken for level 3.

## Decrypting

```bash
ics-pqc-evidence decrypt-archive --input archives/2026-08-05.pqcarch --output restored.jsonl --recipient-private-key keys/archive.key
```

Then verify the evidence itself — decryption proves confidentiality and manifest integrity, not that
the events are sound:

```bash
ics-pqc-evidence verify-log --registry keys/registry.json --input restored.jsonl
```

## Read-side validation

Every check applied when opening an archive:

| Check | Failure code |
|---|---|
| Archive size within limit (default 64 MiB) | `oversized` |
| Valid ZIP | `truncated` |
| Exactly `manifest.json` and `evidence.bin` | `unexpected_entry` / `truncated` |
| No duplicate entries | `duplicate_entry` |
| Entry names are plain file names (no `..`, no absolute paths) | `path_traversal` |
| Manifest parses, has no unknown fields, no missing fields | `bad_manifest` |
| `archive_format_version` supported | `unsupported_version` |
| KEM / KDF / AEAD identifiers are the supported ones | `unsupported_algorithm` |
| Base64 fields decode; nonce is 12 bytes | `bad_manifest` |
| `ciphertext_length` matches the stored payload | `truncated` |
| AES-GCM authentication passes **before any decompression** | `authentication_failed` |
| Decompressed size within limit (default 256 MiB) | `decompression_bomb` |
| `plaintext_sha3_256` and `plaintext_length` match | `digest_mismatch` |

Nothing is ever extracted to a filesystem path from the container, which removes extraction-based
traversal as a class; the name validation is defence in depth.

### ML-KEM implicit rejection

ML-KEM is designed so that decapsulating with the wrong key or a tampered ciphertext yields an
*unpredictable but well-formed* shared secret rather than an error. That is a deliberate property of
FIPS 203, not a missing check: the mismatch surfaces one step later as an AES-GCM authentication
failure. Both the wrong-key and modified-ciphertext cases therefore report `authentication_failed`.

## Sizes

| Component | Size |
|---|---|
| ML-KEM-768 encapsulation (public) key | 1184 B |
| ML-KEM-768 decapsulation (private) key | 2400 B |
| Encapsulated key (ciphertext) | 1088 B |
| Shared secret | 32 B |
| HKDF salt | 32 B |
| AES-GCM nonce | 12 B |
| AES-GCM tag | 16 B |
| Fixed overhead | ~1.2 KB + manifest (~1 KB) |

Signed evidence gzips well, so an archive is usually **smaller** than the plaintext it holds despite
the overhead.

## Operational guidance

* **Archive per node, per period.** One archive per node per day or per incident keeps sequence
  ranges meaningful and limits the blast radius of a lost key.
* **Keep the registry with the archive.** An archive without the public keys that verify its
  contents is much less useful. The registry holds only public material, so store a copy alongside.
* **Back up the ML-KEM private key.** Lose it and the archive is unreadable — there is no recovery
  and that is the intended property.
* **Archives are encrypted, not signed, by this layer.** The events inside are individually signed
  already. The archive adds confidentiality and a bound manifest, not a second signature.
* **Never commit an archive.** `*.pqcarch` and `archives/` are gitignored and excluded from the
  deployment sync.

## Memory behaviour

Creation and reading are both streamed in 1 MiB chunks, so peak memory is bounded by the chunk size
and the zlib window rather than by the archive. Measured on a 25 MB evidence log (WSL2, x86-64,
`tracemalloc` peak over the operation):

| Operation | Peak additional memory |
|---|---|
| create-archive | ~7.4 MB |
| decrypt-archive | ~3.1 MB |

Reading is deliberately **two-pass**: the ciphertext is decrypted and the GCM tag verified in full
*before* a single byte is handed to the decompressor. Authenticating after decompressing would mean
feeding attacker-chosen bytes to zlib, which is how decompression bombs and parser bugs get reached
in the first place. The cost is one extra pass over a temporary file; the benefit is that
`authentication_failed` is reported as an authentication failure rather than surfacing as a
confusing zlib error.

There is no ratio-based bomb heuristic. Signed JSONL legitimately compresses by roughly 1000:1, so
an expansion-ratio limit produces false positives on ordinary input; the absolute
`max_plaintext_bytes` cap is the control that actually works.

## Limitations

* Sealed to exactly one recipient at a time (see below); there is no group or threshold mode.
* No multi-recipient support — one archive is sealed to one ML-KEM public key. Create several
  archives for several recipients. Each is an independent encapsulation; there is no key sharing.
* No partial decryption: it is all or nothing.
* The manifest reveals metadata in the clear: node id, key id, sequence range, event count, times
  and sizes. That is intentional — it lets you triage archives without keys — but it does mean
  **the manifest is not confidential**.
