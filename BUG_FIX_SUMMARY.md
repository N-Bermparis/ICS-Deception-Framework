# Bug Fix Summary — v0.3.0b1

Every defect below was **reproduced before being fixed** and carries at least one regression test
that fails against the previous implementation. Defects are ordered by severity.

Legend: **Sev** — H(igh) affects evidence integrity or availability; M(edium) affects correctness or
security posture; L(ow) affects portability, tooling or accuracy of reporting.

---

## D-01 — Evidence log order could disagree with sequence order · Sev H

**Where:** `pqc_evidence/signer.py` (0.3.0a1)

**What was wrong.** The signer allocated a sequence number under the state lock, released the lock,
and returned the record for the caller to append. Nothing bound file order to sequence order.

**Reproduction.** Two threads signing concurrently, with a delay applied only in the thread that
received sequence 1:

```python
time.sleep(0.5 if rec.sequence == 1 else 0.0)
```

Observed sequence order in `evidence.jsonl`: `[2, 1]`. A naive concurrent test does **not** show
this — the delay must be keyed on the returned sequence, which is why it survived the previous
release.

**Fix.** New `pqc_evidence/evidence_store.py`. One component owns the lock, journal, log and state.
The append happens inside the same lock hold that allocated the sequence, so file order is sequence
order by construction.

**Tests.** `tests/pqc_evidence/test_failure_recovery.py` — concurrent-ordering case driving the
original race; `test_signer.py` — sequence allocation under a shared store.

---

## D-02 — A crash between commit and append lost a signed record permanently · Sev H

**Where:** `pqc_evidence/signer.py`, `state_store.py` (0.3.0a1)

**What was wrong.** Chain state was committed *before* the record was appended. A crash in between
left state claiming a sequence that no record occupied — an unfillable gap. The documented rationale
("losing one record loudly beats silently forging one") was a real trade-off, but it was avoidable.

**Fix.** Write-ahead journal → append → commit, each `fsync`ed, state replaced via `os.replace` with
a directory `fsync`. The journal records the sequence, event hash, target byte offset and the record
itself, so recovery can always tell which side of the append the crash fell on.

**Recovery outcomes:** `completed_commit`, `already_committed`, `rolled_back_partial_append`,
`discarded_unreadable_journal`, `discarded_foreign_journal` — all reported, never silent.

**Tests.** `tests/pqc_evidence/test_failure_recovery.py`, using a `fault` hook that raises at
`before_sign`, `after_sign` and `after_journal`, then asserts the chain is consistent on restart.

---

## D-03 — Committed state ahead of the log was silently tolerated · Sev H

**What was wrong.** If the evidence log was truncated after state was committed, the next signing
run simply continued from state, papering over lost evidence.

**Fix.** `_check_state_against_log()` raises `EvidenceStateDivergence`. Signing halts until an
operator runs `ics-pqc-evidence recover-state --confirm`, which only ever moves state *forward* to
what the log proves. The gap remains visible as `pqc_sequence_gap`.

**Tests.** `test_failure_recovery.py` divergence cases; `test_cli.py::test_recover_state_never_rewinds_past_what_the_log_proves`.

---

## D-04 — `sign_event()` returned an unpersisted record · Sev H

**What was wrong.** The returned record still had to be written by the caller, making
double-appending easy and leaving the durability window above.

**Fix.** `sign_event()` returns only after the record is durably on disk. Documented on the method.

**Tests.** `test_signer.py` asserts the record is present in the log before the call returns.

---

## D-05 — Archive AEAD tag lived in the manifest and was excluded from its own AAD · Sev H

**Where:** `pqc_evidence/archive.py` (format 1.0)

**What was wrong.** `manifest.json` carried an `auth_tag` field, so the AAD computation had to
exclude exactly that field. A fragile special case, and a security-relevant value sitting in the
clear outside the authenticated set.

**Fix.** Archive format **2.0**: no `auth_tag` field; `authenticated_data()` is
`canonical_bytes(self.to_dict())` over the whole manifest; the tag lives only at the end of
`evidence.bin` where the AEAD puts it.

**Tests.** `test_archive.py` — manifest-tampering cases across every field, each expected to fail
authentication.

---

## D-06 — Archive reading decompressed before authenticating · Sev H

**What was wrong.** The streaming read inflated ciphertext-derived bytes and only then checked the
GCM tag. That hands attacker-chosen bytes to zlib — the exact anti-pattern that makes decompression
bombs and parser bugs reachable — and surfaced tampering as a confusing zlib error rather than
`authentication_failed`.

**Fix.** Two-pass `_stream_decrypt`: decrypt and authenticate in full, then decompress.

**Tests.** `test_archive.py` — tampered ciphertext reports `authentication_failed`, not a zlib error.

---

## D-07 — `status` and `recover-state` crashed unconditionally · Sev H

**Where:** `pqc_evidence/cli.py`

**What was wrong.** Both used `add_signer_options()` but not `add_backend_options()`, while
`_build_signer()` reads `args.backend` and `args.algorithm`:

```
AttributeError: 'Namespace' object has no attribute 'backend'
```

Neither command could run at all — including `recover-state`, the documented remedy for D-03.

**Fix.** Both parsers now add the backend options; `_build_signer()` also reads them defensively via
`getattr` with documented defaults.

**Tests.** `test_cli.py` — `test_every_subcommand_has_help` now includes both commands, plus five
behavioural tests that execute them.

---

## D-08 — `status` and `recover-state` could not name the evidence log · Sev H

**What was wrong.** `_build_signer()` resolved the evidence path from `args.output`, which those
commands do not define, so both silently used the default `runtime/pqc/evidence.jsonl`. A node whose
log lived elsewhere reported a false `EvidenceStateDivergence`; worse, `recover-state` would have
repaired state against the wrong file.

**Reproduction.** Sign to `/tmp/st/ev.jsonl`, then run `status` — reported divergence against
`runtime/pqc/evidence.jsonl` and exited 4.

**Fix.** Both commands take `--evidence`; `_build_signer()` accepts `--evidence` or `--output`.

**Tests.** `test_cli.py::test_status_reports_the_chain_position_without_key_material` and the
`recover-state` tests, all of which pass an explicit non-default evidence path.

---

## D-09 — Archives were not actually streamed · Sev M

**What was wrong.** Creation and reading claimed to stream but held the plaintext. A 25 MB evidence
log cost roughly **+37 MB / +36 MB** peak. Two independent causes:

1. `summarise_evidence()` accumulated every line into a list.
2. `decompressor.decompress(chunk, max_plaintext_bytes - written + 1)` let zlib return the entire
   remaining budget in a single call.

**Fix.** Streaming summarisation; a per-chunk `max_length` bound.

**Measured after:** **+7.4 MB** create, **+3.1 MB** decrypt, for the same 25 MB input.

**Tests.** `test_archive.py` memory test using `tracemalloc`. The test itself had to be fixed: it
compared inputs with `read_bytes()`, loading 48 MB and swamping the measurement. It now compares
streaming SHA-256 digests.

---

## D-10 — Compression-ratio bomb heuristic rejected legitimate archives · Sev M

**What was wrong.** `MAX_EXPANSION_RATIO = 200` treated any archive expanding more than 200:1 as a
bomb. Signed JSONL is highly repetitive and legitimately compresses around **1000:1**, so ordinary
archives were rejected.

**Fix.** Removed. The absolute `max_plaintext_bytes` cap is the control that actually bounds
resource use; a ratio limit cannot distinguish a bomb from compressible data.

**Tests.** `test_archive.py` — a realistic multi-thousand-record archive round-trips.

---

## D-11 — Archive verification implied more than it checked · Sev M

**What was wrong.** A successful decryption read as "the archive is verified", when it only proves
the container was sealed to the recipient and its manifest is intact. Whoever built the archive also
wrote its manifest, so `node_id` and the sequence range are self-asserted.

**Fix.** `ArchiveTrust` with six independent booleans — `container_authenticated`,
`plaintext_hash_verified`, `evidence_format_valid`, `evidence_signatures_verified`,
`evidence_chain_verified`, `node_identity_verified` — and `fully_verified` requiring all six.
Authenticating without a key registry emits an explicit warning.

**Tests.** `test_archive.py` trust-model cases, including an archive whose manifest claims a node the
enclosed records contradict.

---

## D-12 — Python services were not wired into the signing path · Sev M

**What was wrong.** `pqc_evidence` existed but no service used it; sealing required running the CLI
by hand, and documentation implied more integration than existed.

**Fix.** `common/publisher.py` — `create_event_publisher()`, `evidence_status()`,
`reset_shared_sink()`. The fake PLC, Modbus honeypot, DNP3 sensor, PCAP loader and controller all
emit through it. The `pqc_evidence` import is deferred so a node without the `[pqc]` extra still
starts. One shared sink per process, so several publishers contribute to one chain.

**Explicitly not claimed:** the native C++ components are not on this path. Documented in README,
SECURITY.md and the threat model.

**Tests.** `tests/pqc_evidence/test_integration_decoys.py` — live services, environment-driven
configuration, verified evidence output.

---

## D-13 — Backends were selected by package name rather than capability · Sev M

**Fix.** Selection probes what a backend can actually do at runtime. A present-but-incapable
install (OpenSSL 3.0.2, which has no ML-DSA) is reported precisely rather than assumed usable.

**Tests.** `tests/pqc_evidence/conftest.py` capability-based fixtures (`pqc_backend`, `kem_backend`,
`every_real_backend`, `openssl_backend`) drive the suite across every genuinely available backend.

---

## D-14 — Unicode and record-size hardening gaps · Sev M

**Fix.** `canonicalizer.py` gained `_check_string()` with an explicit surrogate scan and
`MAX_STRING_LENGTH = 1_000_000`; record-size limits are enforced *before* parsing;
`models.py` gained `_safe_excerpt(value, limit=24)` so error messages cannot echo unbounded
attacker-supplied payloads.

**Tests.** `tests/pqc_evidence/test_hostile_input.py` (56 tests).

---

## D-15 — Metrics did not reflect what happened · Sev L

**Fix.** `EvidenceMetrics` now counts `received`, `signed`, `persisted`,
`rejected_before_signing`, `signing_failures`, `persistence_failures`, `backend_unavailable`,
`state_recoveries`, `verification_successes`, `verification_failures`, `archive_failures`, with
thread-safe `increment()` / `snapshot()`.

---

## D-16 — CRLF line endings broke the deployment script on Linux · Sev L

**What was wrong.** Python's `write_text` on Windows emitted CRLF. `scripts/deploy_rpi.sh` then
failed on Linux with `$'\r': command not found` and tripped ShellCheck SC1017 — an error that names
nothing useful and is invisible in most editors. 32 files were affected.

**Fix.** Normalised the tree; added `.gitattributes` (`* text=auto eol=lf` plus explicit per-suffix
rules); `scripts/make_release.py` normalises text files as they enter the archive, so a checkout on
a filesystem that reintroduces CRLF still ships a correct artifact.

**Tests.** `tests/test_release_hygiene.py` — `.gitattributes` content, `bash -n` on the script as
checked out, and a byte-level check that the *shipped* copy inside the ZIP contains no `\r\n`.

---

## D-17 — `scripts/` was not linted or byte-compiled · Sev L

**What was wrong.** `compileall` and `ruff` covered `src` and `tests` only. A syntax error — an
embedded literal carriage return inside a comment in `scripts/make_release.py` — reached the tree
and broke the release build without any check catching it:

```
File "scripts/make_release.py", line 118
  ': command not found".
SyntaxError: unterminated string literal
```

**Fix.** Repaired the file, and extended `compileall` and `ruff` to `scripts` in the Makefile, CI
and CONTRIBUTING.md.

**Tests.** `tests/test_release_hygiene.py::test_the_release_zip_is_portable_and_clean` and
`::test_the_release_build_is_deterministic` both execute the release builder end to end.

---

## Summary

| Severity | Count |
|---|---|
| High | 8 |
| Medium | 6 |
| Low | 3 |
| **Total** | **17** |

Test suite: **711 tests, 711 passed, 0 failed**. PQC subset: **490 tests, 0 skipped, 0 failures**.
