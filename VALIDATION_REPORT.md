# Validation Report — v0.3.0b1

**Date:** 2026-08-06
**Result:** all executed checks passed. Two checks were **not** executed; both are named explicitly
in [What was not validated](#what-was-not-validated) rather than being reported as passes.

Nothing in this report is asserted unless the command was actually run and its output observed.

---

## Environment

| | |
|---|---|
| Host | Windows 11 Home 10.0.26200 |
| Test environment | WSL2, distro `qns3-ubuntu22` |
| Kernel | Linux 6.6.87.2-microsoft-standard-WSL2 |
| Distribution | Ubuntu 22.04.5 LTS |
| Python | 3.10.12 |
| Compiler | g++ (Ubuntu 12.3.0-1ubuntu1~22.04.3) 12.3.0 |
| Make | GNU Make 4.3 |
| Bash | 5.1.16(1) |
| ShellCheck | 0.11.0 |
| System OpenSSL | 3.0.2 — **no ML-DSA**; probed and correctly reported unusable |
| PQC OpenSSL | 3.5.0 (8 Apr 2025), local build, `ICS_PQC_OPENSSL` |

Python packages: `dilithium-py 1.4.0`, `kyber-py 1.2.0`, `cryptography 50.0.0`, `pytest 9.1.1`,
`pytest-timeout 2.4.0`, `ruff 0.16.1`, `fastapi 0.141.1`, `scapy 2.7.0`, `build 1.5.0`, `pip 26.2.1`.

### Cryptographic capability, as reported by the tool

```
evidence format version : 1.0
default algorithm       : ML-DSA-65
preferred backend       : openssl

  openssl              available    [real PQC]
      version   : OpenSSL 3.5.0 8 Apr 2025
      signatures: ML-DSA-44, ML-DSA-65, ML-DSA-87
      KEMs      : ML-KEM-1024, ML-KEM-512, ML-KEM-768
  pyfips               available    [real PQC]
      version   : 1.4.0 (dilithium-py/kyber-py, pure Python FIPS 204/203)
      signatures: ML-DSA-44, ML-DSA-65, ML-DSA-87
      KEMs      : ML-KEM-512, ML-KEM-768, ML-KEM-1024
  insecure-test-only   available    [TEST ONLY - NO SECURITY]
```

**Two independent real post-quantum backends were exercised.** No test relies on the
`insecure-test-only` backend for a security property; it is never auto-selected and is refused under
`ICS_PQC_PRODUCTION=1`.

---

## Results

| # | Check | Command | Result |
|---|---|---|---|
| 1 | Byte-compile | `python -m compileall -q src tests scripts` | **PASS** |
| 2 | Lint | `python -m ruff check src tests scripts` | **PASS** — "All checks passed!" |
| 3 | CI workflow parses | `yaml.safe_load(.github/workflows/ci.yml)` | **PASS** — 5 jobs |
| 4 | Native clean build | `make clean && make build` | **PASS** — 3 binaries |
| 5 | Zero-warning C++ | rebuild with `-Wall -Wextra -Wpedantic -Werror` | **PASS** |
| 6 | Shell syntax | `bash -n scripts/deploy_rpi.sh` | **PASS** |
| 7 | ShellCheck | `shellcheck scripts/deploy_rpi.sh` | **PASS** — no findings |
| 8 | Full test suite | `python -m pytest -q` | **PASS** — 711 passed, 0 failed |
| 9 | PQC suite, zero skips | `pytest tests/pqc_evidence --junit-xml` | **PASS** — 490 tests, 0 skipped, 0 failures |
| 10 | Packaging | `python -m build` | **PASS** — wheel + sdist |
| 11 | No orphaned processes | `pgrep -f 'modbus_honeypot\|fake_telnet\|fake_ssh'` | **PASS** — 0 leftover |

### Transcript

```
======== 1  compileall ========          PASS
======== 2  ruff ========                All checks passed!   PASS
======== 3  yaml valid ========          ci.yml parses
======== 4  make clean/build ========    PASS
                                         fake_ssh  fake_telnet  modbus_honeypot
======== 5  -Werror ========             PASS
======== 6  bash -n ========             PASS
======== 7  shellcheck ========          PASS
======== 8  pytest (full) ========       711 passed, 1 warning in 65.27s
======== 9  pqc tests, zero skips ====   tests=490 skipped=0 failures=0   PASS
======== 10 python -m build ========     PASS
                                         ics_deception-0.3.0b1-py3-none-any.whl
                                         ics_deception-0.3.0b1.tar.gz
======== 11 no orphaned processes ====   leftover: 0   PASS

======== overall fail flag: 0 ========
```

The single warning is `StarletteDeprecationWarning` from FastAPI's `TestClient`, emitted by the
dependency at import time. It is not a project defect and does not affect behaviour.

---

## Test distribution

**711 tests collected.** 490 in `tests/pqc_evidence/`, 221 elsewhere.

| File | Tests |
|---|---|
| `tests/pqc_evidence/test_models.py` | 83 |
| `tests/test_deploy_script.py` | 69 |
| `tests/pqc_evidence/test_hostile_input.py` | 56 |
| `tests/pqc_evidence/test_archive.py` | 53 |
| `tests/pqc_evidence/test_canonicalizer.py` | 43 |
| `tests/pqc_evidence/test_key_registry.py` | 37 |
| `tests/test_pcap_utils.py` | 36 |
| `tests/pqc_evidence/test_integration_decoys.py` | 34 |
| `tests/test_decoys.py` | 31 |
| `tests/test_controller_api.py` | 31 |
| `tests/pqc_evidence/test_cli.py` | 30 |
| `tests/pqc_evidence/test_state_store.py` | 29 |
| `tests/pqc_evidence/test_signer.py` | 28 |
| `tests/pqc_evidence/test_verifier.py` | 27 |
| `tests/test_modbus_server.py` | 25 |
| `tests/pqc_evidence/test_failure_recovery.py` | 24 |
| `tests/pqc_evidence/test_collector.py` | 24 |
| `tests/pqc_evidence/test_event_chain.py` | 22 |
| `tests/test_release_hygiene.py` | 8 |
| `tests/test_fake_plc.py` | 8 |
| `tests/test_events.py` | 8 |
| `tests/test_modbus_integration.py` | 5 |

**No test was weakened, disabled or marked skipped to reach this result.** The PQC suite is asserted
to have zero skips by parsing the JUnit XML, so a skip introduced later fails validation rather than
passing quietly.

---

## Defect-specific verification

Each defect in [BUG_FIX_SUMMARY.md](BUG_FIX_SUMMARY.md) was reproduced before being fixed. The two
that were hardest to surface:

**D-01, ordering.** A naive concurrent test passes against the broken implementation. Reproduction
required a delay keyed on the returned sequence — `time.sleep(0.5 if rec.sequence == 1 else 0.0)` —
which produced file order `[2, 1]`. Confirmed, then fixed, then the same test used as the regression.

**D-07/D-08, CLI.** `status` and `recover-state` crashed with
`AttributeError: 'Namespace' object has no attribute 'backend'` on every invocation. After that fix,
running `status` against a log at a non-default path reported a false `EvidenceStateDivergence`
(exit 4), confirming the missing `--evidence` option. Both now pass explicit-path tests.

---

## Performance and memory, as measured

Measured on the environment above. These are development-machine numbers, not published benchmarks;
run `ics-pqc-evidence benchmark` on your own hardware.

### Archive memory, 25 MB evidence log (`tracemalloc` peak)

| Operation | Before | After |
|---|---|---|
| create-archive | ~+37 MB | **~+7.4 MB** |
| decrypt-archive | ~+36 MB | **~+3.1 MB** |

Memory no longer scales with archive size. The measurement harness itself was corrected — it had
compared inputs with `read_bytes()`, loading 48 MB and swamping the result; it now compares
streaming SHA-256 digests.

### Signature cost

ML-DSA-65 signing has high variance by construction (rejection sampling). The pure-Python backend is
substantially slower than native OpenSSL and is a portability and CI backend, not the choice for a
busy node. A signed record is ~4.9 KB against ~120 B unsigned, roughly **40×** — on constrained
hardware this storage multiplier, not CPU, is usually the binding constraint.

---

## Release artifact

```
python scripts/make_release.py --output release --keep-directory
```

The builder refuses to produce an archive containing private keys, evidence archives, runtime state,
logs, packet captures, caches, virtual environments or compiled objects, then independently re-opens
the finished ZIP and re-checks it. It also normalises text files to LF on the way in.

Verified on the produced artifact:

- every ZIP entry uses forward slashes, none absolute, none containing `..`
- `scripts/deploy_rpi.sh` retains its executable bit and contains no `\r\n`
- no `.pyc`, `.key`, `.pem`, `.pqcarch`, `.jsonl`, `.log` or `.pcap` entries
- no `.git`, `.venv`, `__pycache__`, `build`, `dist`, `runtime`, `keys` or `*.egg-info` directories
- the build is byte-for-byte reproducible across two runs
- `SHA256SUMS` covers every artifact

These are enforced by `tests/test_release_hygiene.py`, which executes the real builder rather than
trusting it.

---

## What was not validated

Stated plainly, because an unexecuted check must not be reported as a pass.

**1. Raspberry Pi hardware deployment.** No physical Pi was available. `scripts/deploy_rpi.sh` was
validated by `bash -n`, ShellCheck 0.11.0, and 69 tests driving `--dry-run`, argument validation and
the generated systemd unit — including that the unit is user-level, refuses to run as root, carries
its hardening directives, never installs the controller, and never generates a signing key. **No
copy to, install on, or run against real hardware was performed.**

**2. Native C++ services under an actual attack workload.** The binaries were built warning-free
(including `-Werror`), exercised by the integration tests, and CI additionally builds them under
ASan and UBSan. They were **not** subjected to fuzzing or an adversarial traffic campaign.

Additionally:

- **The `insecure-test-only` backend proves nothing about security** and is never used to establish
  a security property. It exists so unit tests can run without a PQC install.
- **Windows locking is not covered by the concurrency tests.** `msvcrt.locking` is implemented, but
  POSIX `flock` is the deployment target and is what the tests exercise.
- **Cross-platform CI runs on `ubuntu-latest` only.** macOS and Windows runners are not configured.

---

## Security constraints observed

| Constraint | Status |
|---|---|
| No TLS, HTTPS, hybrid TLS or VPN functionality added | Held — `pqc_evidence` remains transport-independent |
| No silent fallback to RSA/ECDSA/Ed25519/HMAC/mock in production | Held — unavailable backends raise a structured error |
| No private key in tests, logs, reports, examples, ZIP or tree | Held — asserted by `test_release_hygiene.py` and CLI secret-hygiene tests |
| No key material, shared secrets or full attacker credentials exposed | Held — `status`, `recover-state`, `generate-key` and benchmark output are all tested for it |
| No unbounded attacker-supplied payload echoed | Held — `_safe_excerpt(value, limit=24)` |
| No failure hidden by weakened tests, broad excepts, or skips | Held — zero skips asserted mechanically |
| No claim of legal chain of custody | Held — described throughout as a tamper-evident technical mechanism |
| No claim that native events are signed in real time | Held — the README, SECURITY.md and threat model state that the C++ components are sealed after the fact |
