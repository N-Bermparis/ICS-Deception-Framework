# Signed Evidence Format, version 1.0

The wire and on-disk format for one sealed event. Anything not stated here is not part of the
format and must not be relied on.

## The envelope

One JSON object per line (JSONL), UTF-8, no trailing whitespace:

```json
{
  "format_version": "1.0",
  "node_id": "rpi-honeypot-01",
  "sequence": 154,
  "timestamp": "2026-08-05T18:15:00.000000Z",
  "previous_event_hash": "5ac52ea1365ab2b860dded21f0b3b0c48e0b3f5b0a6f6e4a0b2c1d3e4f5a6b7c",
  "event_hash": "7dcc899972c213eda9267797a4f0c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
  "event": {
    "source": "modbus_honeypot",
    "event_type": "critical_register_write",
    "client_ip": "192.168.1.50",
    "register": 40001,
    "value": 1
  },
  "signature_algorithm": "ML-DSA-65",
  "hash_algorithm": "SHA3-256",
  "key_id": "rpi-honeypot-01-2026-01",
  "signature": "<base64, 3309 bytes decoded>"
}
```

## Field reference

| Field | Type | Rules |
|---|---|---|
| `format_version` | string | Must be `"1.0"`. Any other value is rejected. |
| `node_id` | string | 1–128 chars, `^[A-Za-z0-9][A-Za-z0-9._:-]*$`. No path separators or spaces. |
| `sequence` | integer | ≥ 1, ≤ 2⁶³−1. Strictly monotonic per node, increasing by exactly 1. `true` is **not** accepted as 1. |
| `timestamp` | string | Canonical UTC: `YYYY-MM-DDTHH:MM:SS.ffffffZ`. Must already be in this exact spelling. |
| `previous_event_hash` | string | 64 lowercase hex chars. At sequence 1, the derived genesis value (below). |
| `event_hash` | string | 64 lowercase hex chars. SHA3-256 of the hash payload. |
| `event` | object | The event body. Canonicalizable, ≤ 65 536 canonical bytes, ≤ 16 levels deep. |
| `signature_algorithm` | string | One of `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`. Classical algorithms are rejected. |
| `hash_algorithm` | string | `SHA3-256`. |
| `key_id` | string | Same character rules as `node_id`. |
| `signature` | string | Strict base64 (no whitespace, no non-alphabet characters), non-empty. |

Additional whole-record rules:

* **Unknown fields are rejected.** An unrecognised field could carry unsigned data that a downstream
  consumer mistakes for verified content.
* **Every field is required.**
* **Maximum serialized record size: 262 144 bytes** by default, checked *before* JSON parsing.
* **Duplicate JSON keys are rejected.** `json.loads` keeps the last value silently, so a naive
  reader and a verifier could otherwise disagree about what was signed.
* **`NaN`, `Infinity`, `-Infinity` are rejected** — they are JSON extensions, not JSON.
* **Invalid UTF-8 is rejected.**

## Canonical JSON

Before hashing or signing, the envelope is serialised in a restricted, strictly-typed profile close
to RFC 8785:

* UTF-8, no BOM.
* Object keys sorted by Unicode code point.
* Compact separators: `,` and `:` with no spaces.
* No trailing newline.
* Non-ASCII emitted literally (`ensure_ascii=False`), so the encoding is genuinely UTF-8.

Rejected value types, each because it makes the bytes ambiguous or platform-dependent:

| Rejected | Why |
|---|---|
| `float` (including `1.0`) | Float repr differs across implementations; `1.0` vs `1` is not a distinction worth signing. |
| `NaN`, `±Infinity` | Not valid JSON. |
| `bytes`, `set`, `datetime`, arbitrary objects | No canonical JSON representation. |
| Non-string object keys | JSON keys are strings; coercion would be lossy. |
| Strings with lone surrogates | Not encodable as UTF-8. |
| Nesting deeper than 32 levels | Bounded to stop recursion attacks. |

`bool` is allowed and emitted as `true`/`false`; it is never coerced to a number.

### Test vectors

| Input | Canonical bytes |
|---|---|
| `{}` | `{}` |
| `{"b":2,"a":1}` | `{"a":1,"b":2}` |
| `{ "a" : 1 , "b" : [ 1 , 2 ] }` | `{"a":1,"b":[1,2]}` |
| `{"n":null,"t":true,"f":false}` | `{"f":false,"n":null,"t":true}` |
| `{"unicode":"ü"}` | `{"unicode":"ü"}` (literal, not `ü`) |
| `{"nested":{"y":1,"x":2}}` | `{"nested":{"x":2,"y":1}}` |

Key order and whitespace are irrelevant; **any value change produces different bytes**. Both
directions are asserted in `tests/pqc_evidence/test_canonicalizer.py`.

### Timestamp normalization

`2026-08-05T18:15:00Z`, `2026-08-05T18:15:00+00:00` and `2026-08-05T20:15:00+02:00` are the same
instant but different strings. All are normalised to UTC with microsecond precision and a trailing
`Z` **before** hashing, so semantically identical events produce identical bytes. A timestamp
without a timezone is **rejected** — a naive timestamp is ambiguous.

## What is hashed, and what is signed

Two byte strings are derived from one envelope. Getting these boundaries right is the whole
security argument, so they are stated exactly:

**`event_hash` input** — canonical JSON of the envelope **excluding `event_hash` and `signature`**:

```
{"event":{...},"format_version":"1.0","hash_algorithm":"SHA3-256","key_id":"...",
 "node_id":"...","previous_event_hash":"...","sequence":154,
 "signature_algorithm":"ML-DSA-65","timestamp":"..."}
```

```
event_hash = SHA3-256(that)   →  64 lowercase hex characters
```

**Signature input** — canonical JSON of the envelope **excluding `signature` only**, i.e. including
the `event_hash` just computed:

```
signature = ML-DSA-65.Sign(private_key, canonical_bytes(envelope without "signature"))
```

So the signature covers **every security-relevant field**: `format_version`, `node_id`, `sequence`,
`timestamp`, `previous_event_hash`, `event_hash`, `event`, `signature_algorithm`, `hash_algorithm`
and `key_id`. Only `signature` itself is excluded, for the obvious reason.

Including `event_hash` in the signed bytes is what binds the signature to the chain position: a
signature cannot be lifted from one chain slot and pasted into another.

## The chain

```
sequence 1:  previous_event_hash = SHA3-256("ics-deception/pqc-evidence/genesis/v1/" + node_id)
sequence n:  previous_event_hash = event_hash of sequence n-1
```

### Genesis

A null, empty or all-zero previous hash would be ambiguous: an attacker could truncate a chain to a
single record and claim it was always first, and genesis records would be interchangeable between
nodes. Instead the genesis value is **derived and node-bound**:

```
previous_event_hash = SHA3-256(b"ics-deception/pqc-evidence/genesis/v1/" + node_id.encode("utf-8"))
```

Deterministic, so a verifier recomputes it; unique per node, so a genesis record cannot be moved
between chains. The domain string is versioned inside itself.

## Verification procedure

For each record, in order:

1. Parse and validate the envelope strictly. → `pqc_malformed_evidence` / `pqc_oversized_evidence`
2. Recompute `event_hash` and compare. → `pqc_event_hash_mismatch`
3. Look the key up in the registry and check its status at the event's timestamp.
   → `pqc_unknown_node`, `pqc_unknown_key`, `pqc_revoked_key`, `pqc_expired_key`,
   `pqc_unsupported_algorithm`
4. Verify the ML-DSA signature over the signing payload. → `pqc_invalid_signature`
5. Check chain linkage against this node's cursor. → `pqc_sequence_gap`,
   `pqc_previous_hash_mismatch`, `pqc_duplicate_sequence`, `pqc_replayed_event`,
   `pqc_chain_reset`

All findings are collected; verification does not stop at the first. "Invalid signature *and*
previous-hash mismatch" is a materially different story from either alone.

The chain cursor advances using the **recomputed** hash, never the claimed one. A tampered record
therefore reports its own mismatch and breaks the link to the next record, rather than producing a
cascade of misleading gap alerts — and a forger cannot steer the chain by claiming a hash.

## Verification result

```json
{
  "valid": false,
  "node_id": "rpi-honeypot-01",
  "sequence": 154,
  "event_hash": "ab12...",
  "key_id": "rpi-honeypot-01-2026-01",
  "errors": ["pqc_invalid_signature", "pqc_previous_hash_mismatch"],
  "warnings": [],
  "details": ["ML-DSA signature does not verify against key ..."],
  "verified_at": "2026-08-05T18:20:00Z"
}
```

`errors` are verification **failures** — the record is not trustworthy. `warnings` are observations
that do not by themselves invalidate a record. The two are never conflated.

## Alert vocabulary

| Alert | Meaning |
|---|---|
| `pqc_invalid_signature` | The ML-DSA signature does not verify. |
| `pqc_event_hash_mismatch` | Content does not hash to the stored `event_hash`. |
| `pqc_previous_hash_mismatch` | Chain linkage broken: reordered, spliced or replaced. |
| `pqc_sequence_gap` | Events are missing. |
| `pqc_duplicate_sequence` | Two different events claim one sequence — a fork. |
| `pqc_replayed_event` | The same event appears more than once. |
| `pqc_unknown_node` | No key for this node, or the key belongs to another node. |
| `pqc_unknown_key` | Key not in the registry, or used before activation. |
| `pqc_revoked_key` | Key revoked or disabled. |
| `pqc_expired_key` | Event timestamp is past the key's expiry. |
| `pqc_chain_reset` | A node restarted its chain at sequence 1. |
| `pqc_unsupported_algorithm` | Algorithm identifier not supported, or mismatched with the key. |
| `pqc_malformed_evidence` | The record is not a valid envelope. |
| `pqc_oversized_evidence` | The record exceeds the configured size limit. |

## Compatibility

* **Unsigned logs keep working.** With evidence disabled — the default — the framework writes plain
  JSONL exactly as before.
* **Mixed files.** A file may interleave records from several nodes; each chain is tracked
  independently.
* **Forward compatibility.** A record with a `format_version` this build does not know is rejected,
  not guessed at. Version negotiation is deliberately absent: silently accepting an unknown format
  would mean verifying something you do not understand.
