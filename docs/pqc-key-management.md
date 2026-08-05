# PQC Key Management

How to create, register, rotate and revoke the ML-DSA keys that seal evidence.

> **The one rule that matters:** a private key is generated **on the node that will use it** and
> never leaves that node. Never commit one, never copy one to a workstation, never put one in an
> archive or a benchmark result. The deployment script explicitly excludes `*.pem`, `*.key`,
> `keys/` and `id_rsa*` from everything it copies, and creates no key of its own.

## Key types

| Purpose | Algorithm | Where the private half lives |
|---|---|---|
| Signing evidence | ML-DSA-65 (FIPS 204) | On the deception node |
| Encrypting archives | ML-KEM-768 (FIPS 203) | With the analyst who will open the archive |

They are unrelated. A node needs a signing key; it does **not** need the archive key, and should
never hold one.

## 1. Generate a node signing key

On the node:

```bash
ics-pqc-evidence generate-key --private-key /home/pi/ics-deception/keys/node.key --public-key /home/pi/ics-deception/keys/node.pub
```

Output:

```
generated ML-DSA-65 key pair using the openssl backend
  private key : /home/pi/ics-deception/keys/node.key (mode 0600 - NEVER commit or copy this)
  public key  : /home/pi/ics-deception/keys/node.pub
  fingerprint : 96:c2:be:f9:9a:6d:a9:2d
```

* The private key is written with `O_EXCL` and mode `0600`. Regenerating over an existing key is
  **refused** — losing a signing key means losing the ability to continue that chain.
* The public key is base64 of the raw 1952-byte ML-DSA-65 key.
* The fingerprint is the first 8 bytes of `SHA3-256(public key)`, for comparing by eye.

Pick the backend explicitly if you need to:

```bash
ics-pqc-evidence generate-key --backend openssl --private-key keys/node.key
```

Check what is available first:

```bash
ics-pqc-evidence capabilities
```

## 2. Register the public key with the verifier

Copy **only the `.pub` file** to wherever verification happens:

```bash
scp pi@node:/home/pi/ics-deception/keys/node.pub ./keys/rpi-honeypot-01.pub
```

```bash
ics-pqc-evidence register-key --registry keys/registry.json --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01 --public-key keys/rpi-honeypot-01.pub
```

### Naming keys

`<node-id>-<year>-<sequence>` — e.g. `rpi-honeypot-01-2026-01`. The key id appears in every signed
record, so a readable convention pays for itself when reading a year-old log. Allowed characters:
letters, digits, `.`, `_`, `:`, `-`.

### Activation time

By default a key activates at registration time, and **events signed before that are rejected** —
which is correct: a key should not sign before it exists. If you are registering a key to verify
logs that were signed earlier, say so explicitly:

```bash
ics-pqc-evidence register-key --registry keys/registry.json --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01 --public-key keys/rpi-honeypot-01.pub --activated-at 2026-01-01T00:00:00Z
```

Optionally set an expiry:

```bash
ics-pqc-evidence register-key --registry keys/registry.json --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01 --public-key keys/rpi-honeypot-01.pub --expires-at 2027-01-01T00:00:00Z
```

## 3. Enable signing on the node

Only after a key exists and is registered:

```bash
export ICS_PQC_EVIDENCE_MODE=dual
export ICS_PQC_NODE_ID=rpi-honeypot-01
export ICS_PQC_KEY_ID=rpi-honeypot-01-2026-01
export ICS_PQC_PRIVATE_KEY=/home/pi/ics-deception/keys/node.key
export ICS_PQC_EVIDENCE_LOG=/home/pi/ics-deception/runtime/pqc/evidence.jsonl
export ICS_PQC_STATE=/home/pi/ics-deception/runtime/pqc/state.json
```

Start with `dual` (raw *and* signed) while you gain confidence, then move to `sign`.

If a mode other than `disabled` is set without a usable key, startup **fails loudly**. It never
falls back to unsigned output pretending to be signed, and never creates a key for you.

## Key lifecycle

```
   generate ──▶ register ──▶  ACTIVE  ──┬──▶ rotate ──▶  ROTATED   (history still verifies)
                                        ├──▶ revoke ──▶  REVOKED   (events no longer trusted)
                                        ├──▶ disable ─▶  DISABLED  (administratively off)
                                        └──▶ expiry ──▶  EXPIRED   (past expires_at)
```

| State | New events | Historical events |
|---|---|---|
| `active` | accepted | accepted |
| `rotated` | — | **accepted** |
| `revoked` | rejected | rejected |
| `disabled` | rejected | rejected |
| `expired` | rejected after expiry | accepted before expiry |

## 4. Rotate a key

Rotation replaces the *active* key while keeping every historical signature verifiable. On the node:

```bash
ics-pqc-evidence generate-key --private-key keys/node-2026-02.key --public-key keys/node-2026-02.pub
```

Then, at the verifier:

```bash
ics-pqc-evidence rotate-key --registry keys/registry.json --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-02 --public-key keys/node-2026-02.pub
```

The previous key becomes `rotated`; the new one becomes `active`. Update `ICS_PQC_KEY_ID` on the
node and restart the service.

**Rotation does not reset the chain.** Sequence numbers continue and `previous_event_hash` still
links across the key change, so a rotation is invisible to chain verification — which is the point.

Rotate when: an operator with key access leaves; the node is rebuilt; on a scheduled cadence (annual
is reasonable for a research deployment); or immediately on any suspicion of compromise — and in
that last case, **revoke** as well.

## 5. Revoke a key

```bash
ics-pqc-evidence revoke-key --registry keys/registry.json --key-id rpi-honeypot-01-2026-01 --reason "node seized; private key may be compromised"
```

A reason is mandatory — a revocation without one is unusable six months later. From then on, every
event signed by that key reports `pqc_revoked_key`.

**Revocation is not retroactive truth.** It says "stop trusting signatures from this key". Evidence
collected *before* the suspected compromise is not automatically worthless, but its trustworthiness
becomes a judgement call about timing, not a cryptographic fact. Record when you believe the
compromise happened.

## Registry file

Public keys only — safe to copy, commit to an internal repository, or ship with an archive.

```json
{
  "format_version": "1.0",
  "updated_at": "2026-08-05T18:20:00.000000Z",
  "keys": [
    {
      "key_id": "rpi-honeypot-01-2026-01",
      "node_id": "rpi-honeypot-01",
      "algorithm": "ML-DSA-65",
      "public_key": "<base64 raw 1952 bytes>",
      "public_key_sha3_256": "<64 hex>",
      "fingerprint": "96:c2:be:f9:9a:6d:a9:2d",
      "created_at": "2026-01-01T00:00:00.000000Z",
      "activated_at": "2026-01-01T00:00:00.000000Z",
      "expires_at": null,
      "state": "rotated",
      "revocation_reason": null,
      "revoked_at": null,
      "metadata": {}
    }
  ]
}
```

Written atomically (temp file + `os.replace`), so a crash mid-write cannot truncate it. Rejected on
load: unknown format version, malformed base64, unsupported algorithm, duplicate key ids,
conflicting definitions for one key id, and the same public key registered twice under different
ids (almost always a copy/paste error that would make revocation incomplete).

## Archive keys (ML-KEM-768)

Generated by the **recipient** — the analyst who will open archives:

```python
from ics_deception.pqc_evidence.crypto_backend import select_backend
import base64, pathlib

backend = select_backend(require_kem="ML-KEM-768")
keypair = backend.kem_generate_keypair("ML-KEM-768")
pathlib.Path("archive.pub").write_text(base64.b64encode(keypair.public_bytes).decode())
private = pathlib.Path("archive.key")
private.write_bytes(keypair.private_bytes)
private.chmod(0o600)
```

Distribute `archive.pub` to whoever creates archives. Keep `archive.key` offline. See
[pqc-archive-format.md](pqc-archive-format.md).

## Storage guidance

| Key | Where | Mode | Backup |
|---|---|---|---|
| Node signing private key | On the node only | `0600` | Optional — see below |
| Node signing public key | Registry, widely copied | `0644` | Yes |
| Archive KEM private key | Offline / analyst workstation | `0600` | **Yes** — losing it makes archives unreadable |
| Archive KEM public key | Anywhere | `0644` | Yes |

**Backing up a node signing key is a genuine trade-off.** A backup lets you resume a chain after
hardware failure; it also doubles the number of places the key can leak from. For a honeypot node —
a machine you *expect* to be attacked — not backing up is usually right: if the node dies, register
a new key and accept the visible `pqc_chain_reset`. A reset is auditable; a leaked key is not.

## Compromise response

1. **Revoke** the key with a dated reason.
2. **Do not delete** the old evidence. It is still the record of what happened; it is now evidence
   whose trust boundary you must reason about.
3. **Rebuild** the node, generate a fresh key, register it.
4. **Note the chain reset.** The new chain starts at sequence 1 and verification reports
   `pqc_chain_reset` — intended and correct.
5. **Establish the timeline.** Evidence signed before the compromise may still be sound; evidence
   after it must be treated as attacker-controlled.

## Checklist

- [ ] Private key generated on the node it belongs to
- [ ] Private key mode `0600`, owned by the service user
- [ ] Private key path excluded from backups, syncs and the deployment script
- [ ] Public key registered with the right `node-id`, `key-id` and `activated-at`
- [ ] Fingerprint compared out of band
- [ ] Registry stored where verification happens, not on the node
- [ ] Rotation schedule agreed
- [ ] Revocation procedure documented and tested
- [ ] `git status` shows no key file before every commit
