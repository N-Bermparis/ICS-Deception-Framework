# ICS Deception Framework — v0.3.0b1

**Released:** 2026-08-06
**Status:** beta. The transactional and integration work in this release is complete and validated,
which is why the version moves from `0.3.0a1` to `0.3.0b1` rather than to another alpha.

Research prototype for **authorized laboratory use only**. Read [SECURITY.md](SECURITY.md) before
deploying anything.

---

## Why this release exists

`0.3.0a1` introduced `pqc_evidence`, a post-quantum digital seal for honeypot logs. Reviewing it
under concurrency and failure conditions found that the seal itself was sound but the *persistence
around it* was not: sequence allocation and log appending were separate steps, so the evidence log
could disagree with the chain it claimed to record.

This release makes signing and persistence a single transaction, wires evidence sealing into the
Python services, and corrects the archive trust model so that opening an archive is never mistaken
for verifying its contents.

The project's separation from PQTLS is unchanged: **no TLS, HTTPS, hybrid TLS or VPN functionality
was added.** `pqc_evidence` remains a transport-independent sealing system for logs.

---

## Headline changes

### Evidence persistence is transactional

A new component, `pqc_evidence/evidence_store.py`, owns the lock, the write-ahead journal, the
evidence log and the chain state, and performs the whole operation as one transaction:

```
lock → recover → allocate → hash → sign → journal(fsync)
     → append(fsync) → commit state(atomic+fsync) → drop journal → unlock
```

That yields three guarantees, each with a regression test:

| Guarantee | Previously |
|---|---|
| File order is sequence order | Two concurrent signers reliably produced `[2, 1]` in the log |
| A sequence is issued at most once | Held, but only across the state read-modify-write |
| No committed state without a durable record | State was committed *before* the append, so a crash in between lost a record permanently |

Recovery replays the journal and reports what it did: `completed_commit`, `already_committed`,
`rolled_back_partial_append`, `discarded_unreadable_journal` or `discarded_foreign_journal`. A
partially written record is truncated back to its journalled offset and preserved as
`evidence.jsonl.partial-<epoch>` (mode `0600`) for inspection.

If chain state is ever *ahead* of the log, evidence was lost after being committed. That is not
repairable from inside, so signing halts with `EvidenceStateDivergence` and requires an explicit
`ics-pqc-evidence recover-state --confirm`.

### Evidence sealing is wired into the Python services

`ics_deception.common.publisher.create_event_publisher()` is now the single way Python components
obtain a publisher. With `ICS_PQC_EVIDENCE_MODE` set, each event is signed and durably persisted
before `publish()` returns. The `pqc_evidence` import is deferred, so a node installed without the
`[pqc]` extra still starts and logs normally.

**The native C++ components are not on this path.** `modbus_honeypot`, `fake_telnet` and `fake_ssh`
contain no cryptographic code; they write plain JSONL that is sealed afterwards with `sign-log`.
This is stated in the README, SECURITY.md and the threat model rather than glossed over.

### Archive format 2.0

- The AEAD tag is no longer a manifest field. Format 1.0 stored `auth_tag` in `manifest.json` and
  then had to exclude that one field from its own AAD; 2.0 authenticates the entire manifest and
  keeps the tag where the AEAD puts it.
- Ciphertext is authenticated **before** anything is decompressed. Reading is two-pass.
- Creation and reading are genuinely streamed in 1 MiB chunks — measured at ~7.4 MB and ~3.1 MB peak
  additional memory for a 25 MB log, against roughly +37 MB / +36 MB before.
- The compression-ratio bomb heuristic is gone; signed JSONL legitimately compresses ~1000:1, so it
  produced false positives. The absolute plaintext cap is the control that works.
- `ArchiveTrust` reports six independent facts. `fully_verified` requires all six and is never
  inferred from a subset.

**Archive format 2.0 cannot read 1.0 archives.** Decrypt any 1.0 archives with the previous release
before upgrading.

### CLI repairs

`ics-pqc-evidence status` and `recover-state` previously crashed unconditionally with
`AttributeError: 'Namespace' object has no attribute 'backend'`, and had no way to name the evidence
log — so a node whose log was not at the default path was inspected, or repaired, against the wrong
file. Both now take the backend options and `--evidence`.

---

## Breaking changes

| Change | Action |
|---|---|
| Archive format 1.0 → 2.0 | Decrypt existing archives with 0.3.0a1 first |
| `EvidenceSigner.sign_log(source, max_events=None)` no longer takes a destination | The signer owns its evidence path |
| `sign_event()` returns an already-persisted record | Do not append it again |
| Default archive limits are 64 MiB compressed / 256 MiB plaintext | Raise explicitly if you need more |

---

## Validation

Every command below was executed on the release tree. Full transcript and exact versions in
[VALIDATION_REPORT.md](VALIDATION_REPORT.md).

| Check | Result |
|---|---|
| `compileall src tests scripts` | pass |
| `ruff check src tests scripts` | pass |
| `make clean && make build` | pass — 3 native binaries |
| C++ rebuild with `-Werror` | pass |
| `bash -n` and `shellcheck` on the deploy script | pass |
| Full test suite | **711 passed, 0 failed** |
| PQC suite with zero skips | **490 tests, 0 skipped, 0 failures** |
| `python -m build` | pass — wheel and sdist |
| `.github/workflows/ci.yml` parses | pass — 5 jobs |
| Orphaned processes after the run | none |

Real post-quantum cryptography was exercised, not mocked: the OpenSSL 3.5.0 backend and the
pure-Python FIPS 204/203 backend both ran, and cross-backend interoperability was checked in both
directions.

---

## Upgrading from 0.3.0a1

1. Decrypt any format 1.0 archives before upgrading.
2. Reinstall: `python -m pip install -e ".[dev,pqc]"`.
3. Existing evidence logs and state files are compatible; the evidence envelope format is unchanged
   at 1.0. On first signing run the store will replay any journal it finds and report what it did.
4. If you called `sign_log()` with a destination argument, drop it and set the signer's
   `evidence_path` instead.

---

## Known limitations

Unchanged from the README's *Known limitations*, plus these specific to this release:

- Native C++ honeypot events are sealed after the fact, not as they occur.
- Evidence destroyed after its state was committed cannot be recovered; the gap remains visible as
  `pqc_sequence_gap`.
- Signing costs a synchronous ML-DSA signature plus two `fsync`s per event, which bounds throughput.
  Benchmark before enabling it on a busy node.
- Concurrency is enforced with POSIX `flock`. Windows uses `msvcrt.locking`; POSIX is the deployment
  target and is what the concurrency tests exercise.

This is a **tamper-evident technical mechanism**. It makes no claim about legal chain of custody.
