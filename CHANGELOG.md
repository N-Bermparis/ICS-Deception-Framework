# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Pre-1.0 releases may make
breaking changes in any minor version.

## [Unreleased]

Nothing yet.

## [0.3.0b1] - 2026-08-06

Makes evidence persistence **transactional**, wires evidence sealing into the Python services, and
corrects the archive trust model. Every defect below was reproduced before being fixed, and each
carries a regression test.

### Fixed

**Ordering and durability (the reason for this release)**

- **Record order no longer disagrees with sequence order.** The signer allocated a sequence under
  the state lock, released it, and let the caller append afterwards, so nothing bound file order to
  sequence order. Two concurrent signers reliably produced `[2, 1]` in the evidence log. Signing and
  appending are now a single transaction under a single lock hold, in the new
  `pqc_evidence/evidence_store.py`. The regression test drives the original race directly.
- **A crash no longer permanently loses a signed record.** State was committed *before* the record
  was appended, so a crash in between left an unfillable gap. The order is now write-ahead journal →
  append → commit, each `fsync`ed, with the state file replaced atomically and its directory
  `fsync`ed. On restart the journal is replayed: a complete record is committed, a partial one is
  rolled back (bytes preserved as `evidence.jsonl.partial-<epoch>`, mode 0600) and its sequence
  safely reused. Recovery outcomes are reported, not silent.
- **State ahead of the log is no longer papered over.** It now raises `EvidenceStateDivergence` and
  requires an explicit `ics-pqc-evidence recover-state --confirm`, which only ever moves state
  forward to what the log can prove.
- **`sign_event` no longer returns an unpersisted record.** It returns only after the record is
  durably on disk, so callers can no longer append it a second time.

**Archive**

- **The AEAD tag is no longer carried in the manifest.** Format 1.0 stored `auth_tag` in
  `manifest.json` and then had to exclude that single field from its own AAD. Archive format **2.0**
  authenticates the entire manifest and keeps the tag only where the AEAD puts it, at the end of
  `evidence.bin`.
- **Ciphertext is authenticated before it is decompressed.** Reading previously decompressed and then
  authenticated, feeding attacker-chosen bytes to zlib and surfacing tampering as a confusing zlib
  error instead of `authentication_failed`. Reading is now two-pass.
- **Archives are genuinely streamed.** Creation and reading claimed to stream but held the plaintext:
  a 25 MB log cost roughly +37 MB / +36 MB. Both directions now work in 1 MiB chunks
  (~+7.4 MB / +3.1 MB measured), after fixing `summarise_evidence` accumulating every line and a
  `zlib` call whose `max_length` allowed the whole budget in one return.
- **Removed the compression-ratio bomb heuristic.** Signed JSONL legitimately compresses by around
  1000:1, so the 200:1 limit rejected ordinary archives. The absolute plaintext cap is the control
  that actually works.
- **Verification no longer implies more than it checks.** `ArchiveTrust` reports six independent
  facts; `fully_verified` requires all six and is never inferred from a subset. Authenticating a
  container without a key registry now warns explicitly that the enclosed evidence was not verified.

**CLI**

- **`status` and `recover-state` crashed unconditionally** with
  `AttributeError: 'Namespace' object has no attribute 'backend'` — both omitted the backend options
  that signer construction reads.
- **`status` and `recover-state` could not name the evidence log.** Both silently used the default
  path, so a node whose log lives elsewhere was inspected — or repaired — against the wrong file,
  reporting a false divergence. Both now take `--evidence`.

**Other**

- Backends are selected by **runtime capability**, never by package name.
- Canonicalization rejects lone surrogates via an explicit scan, and bounds string length.
- Record-size limits are enforced before parsing, not after.
- `EvidenceMetrics` counts what actually happened, separating rejected-before-signing, signing
  failures, persistence failures, backend unavailability and recoveries.
- Text files are normalised to LF on the way into the release archive, and `.gitattributes` enforces
  it in the repository. A CRLF `scripts/deploy_rpi.sh` fails on Linux with an error that names
  nothing useful.
- `scripts/` is now covered by `compileall` and `ruff` in the Makefile and CI; it previously was not,
  which let a syntax error reach `make_release.py` unnoticed.

### Added

- `pqc_evidence/evidence_store.py`: transactional store owning the lock, journal, log and state,
  with `append_signed`, `recover`, `status`, `repair_from_log` and a `RecoveryReport`.
- `common/publisher.py`: `create_event_publisher`, `evidence_status` and `reset_shared_sink`. The
  Python services — fake PLC, Modbus honeypot, DNP3 sensor, PCAP loader and controller — now emit
  through it, so events are signed and persisted before `publish()` returns. The native C++
  components are **not** on this path and are sealed after the fact; this is documented rather than
  glossed over.
- `ics-pqc-evidence status` and `recover-state` regression coverage, hostile-input tests, release
  hygiene tests, and PQC coverage for the deployment script.
- `.gitattributes`.

### Changed

- Archive format version **1.0 → 2.0**. HKDF info string is now
  `ics-deception/pqc-evidence/archive/v2`. Version 1.0 archives are not readable by 2.0.
- Default archive limits are 64 MiB compressed / 256 MiB plaintext.
- `EvidenceSigner.sign_log(source, max_events=None)` no longer takes a destination argument; the
  signer owns its evidence path.

## [0.3.0a1] - 2026-08-05

Adds a standalone post-quantum evidence-integrity layer, and repairs a set of defects found by
inspection and by live testing of 0.2.0a1.

### Added

**`pqc_evidence` - a post-quantum digital seal for honeypot logs**

- New package `src/ics_deception/pqc_evidence/` with a versioned signed-event envelope
  (`format_version` 1.0), deterministic canonical JSON, a SHA3-256 hash chain and ML-DSA-65
  (FIPS 204) signatures. Independent of network transport: it works from JSONL files, standard
  input, local queues, offline archives or the existing event publisher, and requires no TLS.
- Strict envelope validation: supported versions and algorithms only, bounded and pattern-checked
  identifiers, monotonic positive sequences, canonical UTC timestamps, SHA3-256 hex hashes, bounded
  nested event size and depth, strict base64, unknown fields rejected, duplicate JSON keys rejected,
  `NaN`/`Infinity` rejected, invalid UTF-8 rejected, and a configurable maximum record size checked
  before parsing.
- Node-bound derived genesis hash rather than a null, empty or all-zero previous hash.
- `crypto_backend.py`: capability-detecting backend abstraction with structured errors. Preferred
  native `openssl` backend (requires OpenSSL 3.5 or newer), a portable pure-Python FIPS 204/203
  backend that interoperates with it byte for byte, and a clearly marked `insecure-test-only`
  backend that is never auto-selected and is refused under `ICS_PQC_PRODUCTION=1`. **No classical
  fallback exists.**
- Private-key format detection, so an OpenSSL PEM and a raw FIPS 204 key are never handed to the
  wrong backend.
- `key_registry.py`: multi-node, multi-key registry with creation, activation and expiry times;
  active / rotated / revoked / expired / disabled states; revocation reasons; fingerprints; atomic
  writes; duplicate and conflict detection; and public import/export. Rotation preserves
  verification of historical events.
- `state_store.py`: crash-safe per-node chain state with an exclusive lock, atomic replace, `0600`
  permissions, corruption detection, explicit recovery, and refusal to reuse or rewind a sequence.
- `verifier.py` and `collector.py`: per-record and stream verification detecting modified, deleted,
  reordered, duplicated, replayed, forked and reset chains, reported through 14 structured `pqc_*`
  alerts.
- `archive.py`: optional encrypted forensic archives - ML-KEM-768, HKDF-SHA-256 and AES-256-GCM,
  with the manifest bound in as additional authenticated data. Rejects modified ciphertext or
  manifest, wrong keys, unsupported algorithms, truncation, oversized archives, unexpected or
  duplicate entries, path traversal and decompression bombs.
- `benchmark.py`: reproducible JSON and CSV benchmarks recording hardware, OS, Python, OpenSSL,
  backend and parameters. Emits no key material.
- `cli.py` (`ics-pqc-evidence`): `capabilities`, `generate-key`, `register-key`, `rotate-key`,
  `revoke-key`, `sign-event`, `sign-log`, `verify-event`, `verify-log`, `create-archive`,
  `decrypt-archive`, `verify-archive` and `benchmark` - each with help, strict validation,
  documented exit codes, a JSON output mode, safe overwrite behaviour and no secret output.
- `integration.py`: `disabled`, `sign`, `dual` and `verify-only` modes on the existing
  `EventPublisher`. **Default `disabled`**; a signing key is never created implicitly; a signing
  failure never loses the plain event.
- Twelve new test modules under `tests/pqc_evidence/`, plus decoy smoke tests and deployment tests.
- Six new documents under `docs/`: PQC architecture, evidence format, key management, threat model,
  archive format and benchmarks.
- `scripts/make_release.py`: builds a portable release ZIP with forward-slash entries, preserved
  executable bits, reproducible timestamps and verified artifact hygiene.
- CI jobs for real PQC (failing if any PQC test skips), AddressSanitizer and UndefinedBehaviorSanitizer
  native builds, clean-environment installation, packaging, ShellCheck and ZIP path portability.

### Fixed

- **Missing `<system_error>` include** in `src/native/modbus_honeypot.cpp` and
  `src/native/common/decoy.h`, where `std::system_error` is caught. GCC 12 supplied it transitively
  through `<thread>`, so this did not fail the build here - it is a latent portability defect that
  breaks on other standard libraries.
- **MBAP length bound inconsistency.** The PCAP loader accepted only 2..253 while the Python and
  C++ servers accept 2..254, so a valid maximum-length Modbus frame was silently ignored by capture
  analysis. Bounds now come from shared constants used everywhere.
- **`GET /logs` read the entire event log into memory** before slicing. It now streams through a
  bounded `collections.deque`, so a multi-gigabyte log cannot exhaust the controller's memory.
- **Zero and negative CLI values were accepted** for packet limits, timeouts, ports, intervals,
  register counts and quantities, silently disabling a limit or making a socket time out
  immediately. All bounded options now use validators in `common/argtypes.py` and exit 2.
- **The native JSONL logger silently dropped every event when its log directory did not exist**
  (found by live testing, not by the test suite). It now creates the directory lazily and retries.
- **The controller ignored `ICS_DECEPTION_PCAP_DIR`** although the example environment file
  documented it as authoritative, so a valid replay returned 404. Precedence is now
  config-then-environment, and documented.
- **The Telnet and SSH decoys reported an over-long line as `login_incomplete`**, indistinguishable
  from a peer hanging up. They now report `line_too_long`.
- **The SSH-banner decoy only recorded a peer's identification string on read failure**, so a real
  SSH client's banner - the single most useful artefact it can capture - was discarded. It is now
  recorded whenever the peer sends one.
- **Native tests reused a prebuilt `build/` binary when present**, so they could pass against stale
  C++ sources. A session fixture now compiles fresh into a temporary directory.
- **Release ZIPs could contain Windows backslash paths** and lose the executable bit on
  `scripts/deploy_rpi.sh`. The release script writes and then independently verifies both.
- **`load_public_key_file` contained a leftover no-op expression.**

### Changed

- Version 0.2.0a1 to **0.3.0a1**.
- `scripts/deploy_rpi.sh` gains `--dry-run`, a single-source-of-truth remote script, stricter
  argument validation, and exclusions for private keys, evidence archives, chain state and local
  controller configuration. Passes `bash -n` and ShellCheck.
- Every `your-org` placeholder replaced with a single documented `OWNER` token.
- `EventPublisher` accepts an optional evidence sink. With none - the default - behaviour is
  byte-for-byte what it was.

### Security

- Private keys are written `0600` with `O_EXCL`, never overwritten, never logged, never included in
  benchmarks, archives or the release ZIP, and excluded from the deployment sync.
- CI fails if a key, capture, log, archive or cache is ever tracked in git, or if a release ZIP
  contains one.

## [0.2.0a1] — 2026-08-05

A near-total rewrite that turns a broken prototype into a runnable, tested research framework.

### Added

**Packaging and tooling**
- Installable package `ics-deception` under `src/ics_deception/` with a `pyproject.toml`
  (Python 3.10+), pinned dependency groups and five console entry points: `ics-controller`,
  `ics-modbus-server`, `ics-dnp3-sensor`, `ics-fake-plc`, `ics-pcap`.
- Root `Makefile` with `install`, `install-dev`, `build`, `test`, `lint`, `check`, `run`, `clean`.
- GitHub Actions CI for Python 3.12: byte-compile, ruff, C++ build with `-Wall -Wextra -Wpedantic`
  (plus a second `-Werror` pass), pytest, `bash -n`, and a guard that fails if binaries, captures or
  logs are ever tracked. Minimal `contents: read` permissions.
- `ics_deception.common.paths` centralises runtime path resolution behind
  `ICS_DECEPTION_RUNTIME_DIR`, `ICS_DECEPTION_EVENT_LOG` and `ICS_DECEPTION_PCAP_DIR`.
- `ics_deception.common.modbus` with shared MBAP framing helpers.

**Modbus/TCP honeypot (C++)**
- MBAP-length-driven frame reassembly: requests split across multiple `recv()` calls are
  reconstructed, and multiple requests in one TCP segment are all serviced.
- Validation of the protocol identifier, the declared MBAP length, function-specific PDU lengths,
  register addresses, quantities, values and byte counts.
- Exact-size (9 byte) exception responses that never echo bytes from a malformed request.
- Reliable `send_all`, receive timeouts, a simultaneous-client limit, and bounded frame and
  reassembly buffers.
- CLI options: `--bind`, `--port`, `--error-percent`, `--min-latency-ms`, `--max-latency-ms`,
  `--seed`, `--max-clients`, `--crit-start`, `--crit-end`, `--timeout`, `--log`, `--help`.
- JSONL events for connections, closed connections, requests, responses, malformed frames, timeouts
  and connection errors, rejected connections, and writes to simulated critical registers.

**Python services**
- `honeypots/modbus_server.py`: standard-library Modbus/TCP server (FC03/FC06) with MBAP length
  parsing, stream buffering, exception responses and structured logging.
- `honeypots/dnp3_sensor.py`: DNP3-*inspired* interaction sensor with socket timeouts, bounded
  session sizes, bounded payload samples, reusable addresses and per-client threads.
- `iot_nodes/fake_plc.py`: polls with valid FC03 requests and writes its state atomically.

**Controller**
- Endpoints `GET /health`, `GET /status`, `GET /logs`, `GET /ics-values`,
  `POST /components/{name}/start`, `POST /components/{name}/stop`, `POST /replay`.
- Pydantic-validated JSON configuration; per-component enable/disable and autostart.
- Child processes run in their own process group with stdout/stderr redirected to per-component log
  files, started with `sys.executable` for Python components.
- Guarded replay: extension allowlist, approved-directory containment after path resolution,
  traversal rejection, packet-count limit, single-job locking, output to a runtime log file.
- Modern `lifespan` startup/shutdown handling with clean process-group teardown.

**PCAP tooling**
- Streaming analysis via Scapy `PcapReader`; IPv4 and IPv6 endpoint extraction; Modbus protocol-ID
  and MBAP length validation; bounded metadata; summary counters.
- Replay gated behind `--replay`, restricted to client-to-server payloads, with configurable targets
  and a maximum packet count. Individual replay failures are logged without aborting the analysis.

**Interactive decoys**
- Bounded line and command lengths, receive timeouts, client limits, loopback binding, JSONL
  logging, and a shared `src/native/common/decoy.h` scaffold.
- Passwords are **not** stored by default: only length and a character-class shape are logged.
  `--capture-credentials` opts in explicitly.

**Testing**
- 110 tests: JSONL event creation and field structure, PCAP path validation, traversal and symlink
  escape rejection, unsupported extensions, `HOST:PORT` parsing, Python Modbus FC03/FC06,
  unsupported-function exceptions, controller health/status/logs/replay, missing PLC state, atomic
  state writes, and configuration validation.
- Native integration test: builds or locates the binary, picks a free unprivileged port, starts the
  honeypot, sends a request across multiple TCP writes, verifies reassembly, writes a critical
  register with FC06, reads it back with FC03, stops the process and asserts a `sabotage_detected`
  event was logged.

**Documentation**
- Rewritten `README.md`; new `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `CITATION.cff`,
  `GITHUB_UPLOAD_CHECKLIST.md`, `.env.example`, and `docs/architecture.md`,
  `docs/threat-model.md`, `docs/experiments.md`.
- A comprehensive `.gitignore` covering binaries, captures, logs, caches, virtualenvs and secrets.

### Fixed

- **Invalid Python indentation** made `honeypots/modbus_honeypot.py`, `iot-nodes/.../fake_plc.py`
  and `tests/modbus_attack_test.py` unparseable. All three were rewritten.
- **C++ compilation error**: `std::stringresp;` in `fake_telnet.cpp` (missing space).
- **The fake PLC sent the literal string `HEARTBEAT`** instead of a Modbus request, so the honeypot
  only ever logged malformed frames. It now issues a valid FC03 request and parses the reply.
- **The fake PLC's state file was written non-atomically**, letting `/ics-values` read a truncated
  document. Writes now go to a temporary file in the same directory followed by `os.replace`.
- **Controller commands were missing required arguments** (for example `fake_plc.py` with no target)
  and referenced paths that did not exist (`iot-nodes/raspberrypi`, `honeypots/modbus_honeypot`).
- **Child processes used unread `subprocess.PIPE` handles**, which fill their OS buffer and block the
  child. Output now goes to per-component log files.
- **The controller bound to `0.0.0.0` and started every service on boot.** It now binds loopback and
  starts nothing without explicit opt-in.
- **`/logs` returned strings containing JSON.** It now returns parsed objects.
- **Replay accepted an arbitrary path from a query parameter** with no validation whatsoever. It is
  now extension-checked, resolved, containment-checked, bounded and serialised.
- **The honeypot listened on privileged port 502 on `0.0.0.0`,** requiring root. Default is now
  `127.0.0.1:5020`, with port-forwarding documented.
- **`rdpcap` loaded entire captures into memory**; replaced with streaming `PcapReader`.
- **Fragile `sys.path` manipulation and `from common.events` imports** replaced with absolute package
  imports.
- **The Raspberry Pi deployment script** referenced a misspelled directory, installed from a
  `requirements.txt` reached by a broken relative path, took the host as a bare positional argument,
  and launched the node with `nohup` and no supervision. It now takes named options, syncs with
  exclusions, installs the package from `pyproject.toml`, builds the native components and installs
  a hardened user-level systemd unit.
- **The C++ honeypot echoed request bytes into exception responses** and could return trailing
  garbage from malformed frames.
- **`inet_ntoa` (not thread-safe) and `system("mkdir -p logging")`** replaced with `inet_ntop` and
  direct file handling.
- **Random error injection was always on at ~5%**, making behaviour non-deterministic. It is now off
  by default and seedable.

### Changed

- Directory `src/iot-nodes/rasberrypi/` (misspelled) → Python code in `src/ics_deception/iot_nodes/`,
  C++ code in `src/native/`.
- The DNP3 component is renamed and re-documented as an *interaction sensor*, and the SSH component
  as an *SSH-banner decoy*, to stop implying protocol conformance.
- Default Modbus port is 5020 (unprivileged) everywhere; forwarding from 502 is documented.
- Event timestamps use timezone-aware `datetime.now(timezone.utc)` instead of the deprecated
  `utcnow()`.

### Removed

- Placeholder files `data/temp`, `docs/temp`, `data/raw/empty`, the empty `requirements.txt`
  (superseded by `pyproject.toml`) and the empty `src/logging/elk-compose.yml`.
- The `pymodbus` dependency; the Python Modbus server is now standard-library only.
- The ESP32/Arduino build path (`src/main.cpp` and the `#ifdef ARDUINO` branches). It referenced a
  function that no longer exists, could not be compiled or tested in CI, and was untested in
  practice. An ESP32 port is on the roadmap.

## [0.1.0] — prior state

Initial prototype presented at FOSSCOMM 2024 and ECESCON 2025. Several source files did not parse or
compile; see the *Fixed* section above.

[Unreleased]: https://github.com/N-Bermparis/ICS-Deception-Framework/compare/v0.3.0b1...HEAD
[0.3.0b1]: https://github.com/N-Bermparis/ICS-Deception-Framework/releases/tag/v0.3.0b1
[0.3.0a1]: https://github.com/N-Bermparis/ICS-Deception-Framework/releases/tag/v0.3.0a1
[0.2.0a1]: https://github.com/N-Bermparis/ICS-Deception-Framework/releases/tag/v0.2.0a1
