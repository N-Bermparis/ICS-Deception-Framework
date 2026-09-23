# ICS Deception Framework

A lightweight, distributed deception and telemetry framework for Industrial Control System
research. It combines a native C++ Modbus/TCP honeypot, a DNP3-inspired interaction sensor,
interactive Telnet and SSH-banner decoys, a fake PLC node for Raspberry Pi class hardware, and a
loopback-bound FastAPI controller. Every component emits the same structured JSONL event stream, so
a whole deception fabric produces one analysable telemetry file. It also ships passive PCAP analysis
with an explicitly opt-in, bounded replay mode for driving captured ICS traffic at your own
laboratory targets. An optional post-quantum evidence layer (`pqc_evidence`) can seal those logs
with ML-DSA-65 signatures over a SHA3-256 hash chain, so that later tampering with the record
becomes detectable.

> ### ⚠️ Status: alpha research prototype
>
> This is **not production software** and it is **not a certified protocol implementation**. It is a
> research prototype for **authorized laboratory use only**. The protocol services implement small,
> deliberately incomplete subsets of Modbus and DNP3 for deception purposes. Interfaces, event
> schema and configuration format may change without notice. See
> [Known limitations](#known-limitations) and [SECURITY.md](SECURITY.md) before you run anything.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Repository structure](#repository-structure)
- [Installation](#installation)
- [Building the C++ components](#building-the-c-components)
- [Running the tests](#running-the-tests)
- [Quick start: local Modbus honeypot](#quick-start-local-modbus-honeypot)
- [Running the controller](#running-the-controller)
- [API endpoints](#api-endpoints)
- [PCAP analysis and replay](#pcap-analysis-and-replay)
- [Post-quantum evidence sealing](#post-quantum-evidence-sealing)
- [Raspberry Pi deployment](#raspberry-pi-deployment)
- [Log locations](#log-locations)
- [Security and ethical use](#security-and-ethical-use)
- [Known limitations](#known-limitations)
- [Academic presentations](#academic-presentations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Citation](#citation)
- [License](#license)

---

## Features

| Component | Language | What it does |
|---|---|---|
| **Modbus/TCP honeypot** | C++17 | FC01/03/05/06/16 over a real MBAP state machine: length-driven frame reassembly, strict field validation, exact-size exception responses, per-connection timeouts, client limits, critical-register sabotage alerts |
| **Modbus deception server** | Python | Dependency-free FC03/FC06 subset for demos and tests |
| **DNP3 interaction sensor** | Python | Records probes on TCP/20000 with bounded payload samples — *not* a DNP3 outstation |
| **Telnet decoy** | C++17 | Fake RTU maintenance shell with bounded lines, timeouts and command logging |
| **SSH-banner decoy** | C++17 | Emits an SSH identification string and a fake shell — *no* key exchange, *not* an SSH server |
| **Fake PLC node** | Python | Polls the honeypot with valid FC03 requests; publishes state atomically |
| **Controller** | Python / FastAPI | Loopback REST API for status, logs, PLC values, component lifecycle and guarded replay |
| **PCAP tooling** | Python / Scapy | Streaming passive analysis; opt-in, bounded, client-to-server-only replay |
| **PQC evidence seal** | Python | Optional ML-DSA-65 signatures over a SHA3-256 chain: detects modified, deleted, reordered, duplicated and replayed events |
| **Encrypted archives** | Python | Optional offline evidence archives: ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM |
| **Structured telemetry** | all | One JSONL schema shared by the Python and C++ components |

Safe-by-default design: every service binds to **loopback**, uses **unprivileged ports**, needs **no
root**, injects **no random errors** unless asked, starts **nothing** automatically, and stores **no
plaintext passwords** unless a controlled experiment explicitly opts in.

## Architecture

```
                       ┌──────────────────────────────────────────┐
                       │        FastAPI Controller (loopback)     │
                       │  /health /status /logs /ics-values       │
                       │  /components/{name}/start|stop  /replay  │
                       └───────┬─────────────────────────┬────────┘
                               │ supervises              │ reads
                     (own process groups,                │
                      stdout → per-component log)        │
          ┌────────────────────┼─────────────────┐       │
          ▼                    ▼                 ▼       │
  ┌───────────────┐   ┌────────────────┐  ┌───────────┐  │
  │ Modbus/TCP    │   │ DNP3-inspired  │  │  Telnet   │  │
  │ honeypot      │   │ sensor         │  │  + SSH    │  │
  │ (C++, :5020)  │   │ (Py, :20000)   │  │  decoys   │  │
  └───────┬───────┘   └───────┬────────┘  └─────┬─────┘  │
          │                   │                 │        │
          │ FC03 polls        │                 │        │
  ┌───────┴───────┐           │                 │        │
  │ Fake PLC node │           │                 │        │
  │ (Raspberry Pi)│           │                 │        │
  └───────┬───────┘           │                 │        │
          │ plc_state.json    │                 │        │
          │ (atomic write)    │                 │        │
          ▼                   ▼                 ▼        │
     ┌─────────────────────────────────────────────┐     │
     │   runtime/events.jsonl  (shared JSONL bus)  │◀────┘
     └─────────────────────┬───────────────────────┘
                           │
                    ┌──────┴───────┐
                    │ PCAP tooling │  passive analysis (default)
                    │  (Scapy)     │  active replay (--replay only)
                    └──────────────┘
```

Data flow in one sentence: attacker traffic hits a deception service, the service answers in
protocol and appends a structured event to the shared JSONL bus, and the controller exposes that bus
plus the fake PLC's current state over a loopback REST API.

## Repository structure

```
.
├── .github/workflows/ci.yml        # CI: compileall, ruff, C++ build, pytest, bash -n
├── config/
│   └── controller.example.json     # Example controller config (all components disabled)
├── data/
│   ├── pcaps/                      # Approved capture directory — captures are NEVER committed
│   └── raw/                        # Scratch space for dataset work
├── docs/
│   ├── architecture.md             # Component and data-flow design
│   ├── threat-model.md             # Assets, adversaries, trust boundaries, residual risk
│   ├── experiments.md              # Reproducible laboratory experiment protocols
│   ├── pqc-evidence-architecture.md
│   ├── pqc-evidence-format.md      # The signed envelope, canonical JSON, the chain
│   ├── pqc-key-management.md       # Generate, register, rotate, revoke
│   ├── pqc-threat-model.md         # What the seal does and does NOT protect against
│   ├── pqc-archive-format.md       # ML-KEM-768 + HKDF + AES-GCM archives
│   └── pqc-benchmarks.md           # Measured cost, and how to reproduce it
├── scripts/
│   ├── deploy_rpi.sh               # Unprivileged Raspberry Pi deployment (user systemd unit)
│   └── make_release.py             # Portable release ZIP with verified path hygiene
├── src/
│   ├── ics_deception/              # Installable Python package
│   │   ├── common/                 #   events.py, modbus.py, paths.py
│   │   ├── controller/             #   app.py, cli.py, config.py, process.py
│   │   ├── datasets/               #   pcap_loader.py, pcap_utils.py
│   │   ├── honeypots/              #   modbus_server.py, dnp3_sensor.py
│   │   └── iot_nodes/              #   fake_plc.py
│   └── native/                     # C++17 sources
│       ├── common/                 #   net_util.h, decoy.h
│       ├── modbus_honeypot.cpp
│       ├── fake_telnet.cpp
│       ├── fake_ssh.cpp
│       └── Makefile
├── tests/                          # Unit tests + native split-frame integration test
├── Makefile                        # install, install-dev, build, test, lint, check, run, clean
└── pyproject.toml                  # Packaging, dependencies, entry points, ruff, pytest
```

## Installation

Requires **Python 3.10+**, and `g++` with `make` for the native components.

```bash
git clone https://github.com/N-Bermparis/ICS-Deception-Framework.git
```

### Virtual environment setup

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

On Windows use `.venv\Scripts\activate` instead. Then install the package — runtime only, or with
the development tools:

```bash
make install
```

```bash
make install-dev
```

`make install-dev` performs an editable install with pytest, ruff, httpx, build and Scapy.

Copy the example environment and controller configuration before first run:

```bash
cp .env.example .env
```

```bash
cp config/controller.example.json config/controller.json
```

## Building the C++ components

All three native targets build with `-Wall -Wextra -Wpedantic` into `build/`, which is gitignored:

```bash
make build
```

Equivalent direct invocation:

```bash
make -C src/native BUILD_DIR="$PWD/build" all
```

Remove the binaries again with `make clean`.

## Running the tests

```bash
make test
```

Or the whole gate — byte-compile, lint, native build, tests and shell syntax check:

```bash
make check
```

Run only the fast unit tests, skipping the native integration test:

```bash
python -m pytest -m "not integration"
```

The suite uses only unprivileged loopback ports, needs no external network, injects no randomness,
and writes every artifact into pytest temporary directories.

## Quick start: local Modbus honeypot

Start the native honeypot on loopback port 5020:

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --log runtime/modbus.jsonl
```

Or the pure-Python server, if you have not built the native one:

```bash
python -m ics_deception.honeypots.modbus_server --host 127.0.0.1 --port 5020
```

Point the fake PLC at it and take a single reading:

```bash
python -m ics_deception.iot_nodes.fake_plc --target-host 127.0.0.1 --target-port 5020 --once
```

Full option list for the native honeypot:

```bash
./build/modbus_honeypot --help
```

It supports `--bind`, `--port`, `--error-percent`, `--min-latency-ms`, `--max-latency-ms`, `--seed`,
`--max-clients`, `--crit-start`, `--crit-end`, `--timeout` and `--log`. Random error injection is
**off by default** (`--error-percent 0`) so experiments and tests stay deterministic.

### Using the real Modbus port (502)

Port 502 is privileged. Rather than running a honeypot as root, keep it on 5020 and redirect, on an
isolated laboratory host only:

```bash
sudo nft add rule inet nat prerouting tcp dport 502 redirect to :5020
```

Or with iptables:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 502 -j REDIRECT --to-port 5020
```

## Running the controller

The controller binds to `127.0.0.1:8000` and starts **no** components automatically:

```bash
make run
```

Equivalent explicit invocation:

```bash
python -m ics_deception.controller.cli --config config/controller.json --host 127.0.0.1 --port 8000
```

Generate a fresh default configuration:

```bash
python -m ics_deception.controller.cli --write-default-config config/controller.json
```

To let the controller manage a component, set `"enabled": true` for it in the configuration, then
start it through the API. Set `"autostart": true` as well if it should come up with the controller.

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness plus a summary of the effective configuration |
| `GET` | `/status` | Per-component supervision state and any active replay job |
| `GET` | `/logs?limit=N` | Last *N* events as **parsed JSON objects** (not JSON-in-strings) |
| `GET` | `/ics-values` | Last fake PLC reading; `404` when no state file exists |
| `POST` | `/components/{name}/start` | Start one component (`404` unknown, `409` disabled) |
| `POST` | `/components/{name}/stop` | Stop one component |
| `POST` | `/replay` | Controlled PCAP replay (`400` bad extension, `403` traversal, `404` missing, `409` busy) |

```bash
curl http://127.0.0.1:8000/health
```

```bash
curl "http://127.0.0.1:8000/logs?limit=20"
```

```bash
curl -X POST http://127.0.0.1:8000/components/modbus_python/start
```

Interactive OpenAPI documentation is served at `http://127.0.0.1:8000/docs`.

## PCAP analysis and replay

Passive analysis is the default and transmits nothing. Captures are streamed with Scapy's
`PcapReader`, so memory use does not grow with file size:

```bash
python -m ics_deception.datasets.pcap_loader --pcap data/pcaps/sample.pcap
```

It prints summary counters (`packets_seen`, `packets_matched`, `packets_replayed`, `errors`) and
writes per-packet metadata events to the JSONL log.

Replay requires the explicit `--replay` flag and **transmits real traffic**. Only client-to-server
payloads are sent, only to the targets you name, and only up to `--max-packets`:

```bash
python -m ics_deception.datasets.pcap_loader --pcap data/pcaps/sample.pcap --replay --modbus-target 127.0.0.1:5020 --dnp3-target 127.0.0.1:20000 --max-packets 500
```

Through the controller, replay is additionally restricted to the approved capture directory, rejects
path traversal, and permits one job at a time:

```bash
curl -X POST http://127.0.0.1:8000/replay -H 'Content-Type: application/json' -d '{"pcap_path": "sample.pcap", "max_packets": 500}'
```

## Post-quantum evidence sealing

`pqc_evidence` is a **post-quantum digital seal for honeypot logs**. It helps prove that a recorded
event really came from a trusted honeypot node and was not secretly changed, deleted, reordered or
replayed afterwards.

> **It is not TLS.** It does not encrypt Modbus or DNP3 connections, does not prevent attacks, does
> not stop an attacker from deleting a compromised device's entire log, and does not guarantee legal
> chain of custody. It protects the **verifiability of recorded evidence**, nothing more.
> Transport security (PQTLS) is maintained as a separate project.

It is **disabled by default**: with no configuration the framework writes plain unsigned JSONL
exactly as it always has, and no cryptographic dependency is required.

### How it works

Each node keeps a hash chain. Every event is wrapped in a versioned envelope carrying the previous
event's hash, gets a SHA3-256 hash of its own, and is signed with an ML-DSA-65 (FIPS 204) private
key that never leaves the node. A verifier holding only the node's **public** key re-derives every
hash and checks every signature.

Signing and persisting are **one transaction**, not two steps. A single component holds the lock,
writes a write-ahead journal, appends the record, then commits the chain state — each step
`fsync`ed. That gives three guarantees:

* **Order.** Record *n+1* never appears before record *n* in the file, even under concurrent
  writers, because the append happens inside the same lock hold that allocated the sequence.
* **Single use.** A sequence number is issued at most once, enforced by a `flock` across processes,
  with a bounded timeout rather than an indefinite block.
* **Crash safety.** A crash at any point leaves the chain consistent. On restart the journal is
  replayed: a fully written record is committed, a partial one is rolled back (its bytes preserved
  for inspection) and its sequence safely reused.

If chain state is ever *ahead* of the log, signed records were lost, and the framework refuses to
guess — it stops and requires an explicit `ics-pqc-evidence recover-state --confirm`. See
[pqc-evidence-architecture.md](docs/pqc-evidence-architecture.md) for the full recovery table.

Inspect a node's chain at any time:

```bash
ics-pqc-evidence status --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01 --private-key keys/node.key --evidence runtime/pqc/evidence.jsonl
```

### Enabling it

Install the optional post-quantum dependencies:

```bash
python -m pip install -e ".[pqc]"
```

Check what cryptography is actually available on this machine:

```bash
ics-pqc-evidence capabilities
```

The native OpenSSL backend is preferred and needs **OpenSSL 3.5 or newer**; the portable pure-Python
FIPS 204/203 backend works everywhere and interoperates with it byte for byte.

### Generate and register a node key

On the node — a private key is generated where it will be used and never copied:

```bash
ics-pqc-evidence generate-key --private-key keys/node.key --public-key keys/node.pub
```

At the verifier, register the **public** half:

```bash
ics-pqc-evidence register-key --registry keys/registry.json --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01 --public-key keys/node.pub
```

### Sign a log

Sign an existing unsigned log in one batch:

```bash
ics-pqc-evidence sign-log --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01 --private-key keys/node.key --state runtime/pqc/state.json --input runtime/events.jsonl --output runtime/pqc/evidence.jsonl
```

Or sign continuously as events are emitted, by setting these before starting a service:

```bash
export ICS_PQC_EVIDENCE_MODE=dual ICS_PQC_NODE_ID=rpi-honeypot-01 ICS_PQC_KEY_ID=rpi-honeypot-01-2026-01 ICS_PQC_PRIVATE_KEY=keys/node.key
```

Modes: `disabled` (default), `sign` (signed only), `dual` (both raw and signed), `verify-only`.

#### Which events are signed as they happen

Be precise about this, because it is easy to assume more than is true.

| Component | Signed in real time? |
|---|---|
| `ics-fake-plc`, Python Modbus honeypot, DNP3 sensor, PCAP loader, controller | **Yes.** They emit through `create_event_publisher`, so each event is signed and persisted before the call returns. |
| Native C++ `modbus_honeypot`, `fake_telnet`, `fake_ssh` | **No.** They write their own JSONL directly and contain no cryptographic code. |

The C++ binaries are deliberately dependency-free — adding ML-DSA to them would mean linking a PQC
library into every honeypot process. Seal their output after the fact instead:

```bash
ics-pqc-evidence sign-log --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-01 --private-key keys/node.key --state runtime/pqc/state.json --input runtime/modbus_honeypot.jsonl --output runtime/pqc/evidence.jsonl
```

Batch signing gives the same chain and the same signatures; what it does not give is a bound on how
long an event sits unsigned on disk, where an attacker with write access could still alter it. That
window is the honest trade-off, and it is why the table above matters.

### Verify evidence

```bash
ics-pqc-evidence verify-log --registry keys/registry.json --input runtime/pqc/evidence.jsonl
```

```
evidence log verification: VALID
  records   : 154
  verified  : 154
  failed    : 0
  node rpi-honeypot-01: 154 event(s), last sequence 154
```

Exit code `0` means every record verified; `1` means at least one did not. Machine-readable output:

```bash
ics-pqc-evidence --json verify-log --registry keys/registry.json --input runtime/pqc/evidence.jsonl
```

Tampering is reported with a specific alert — `pqc_invalid_signature`, `pqc_event_hash_mismatch`,
`pqc_previous_hash_mismatch`, `pqc_sequence_gap`, `pqc_duplicate_sequence`, `pqc_replayed_event`,
`pqc_unknown_node`, `pqc_unknown_key`, `pqc_revoked_key`, `pqc_expired_key`, `pqc_chain_reset`,
`pqc_unsupported_algorithm`, `pqc_malformed_evidence`, `pqc_oversized_evidence`.

### Rotate and revoke

```bash
ics-pqc-evidence rotate-key --registry keys/registry.json --node-id rpi-honeypot-01 --key-id rpi-honeypot-01-2026-02 --public-key keys/node-2026-02.pub
```

```bash
ics-pqc-evidence revoke-key --registry keys/registry.json --key-id rpi-honeypot-01-2026-01 --reason "node seized"
```

Rotation preserves history: events signed by the old key keep verifying, while new events must use
the new active key.

### Optional encrypted archives

For moving evidence offline. ML-KEM-768 establishes a shared secret, HKDF-SHA-256 derives a key, and
AES-256-GCM encrypts — with the manifest bound in as authenticated data:

```bash
ics-pqc-evidence create-archive --input runtime/pqc/evidence.jsonl --output archives/2026-08-05.pqcarch --recipient-public-key keys/archive.pub --node-id rpi-honeypot-01
```

```bash
ics-pqc-evidence decrypt-archive --input archives/2026-08-05.pqcarch --output restored.jsonl --recipient-private-key keys/archive.key
```

Both directions are streamed in 1 MiB chunks, so memory does not scale with archive size, and the
GCM tag is verified **before** anything is decompressed.

**Opening an archive is not the same as trusting its contents.** Decryption proves the container was
sealed to you and its manifest is intact; it says nothing about whether the enclosed events are
genuine, since whoever built the archive also wrote its manifest. Pass a registry to check the
evidence itself:

```bash
ics-pqc-evidence verify-archive --input archives/2026-08-05.pqcarch --recipient-private-key keys/archive.key --registry keys/registry.json
```

Only that form can report `fully_verified`. Without `--registry` the tool warns explicitly that the
enclosed evidence was not verified. See
[pqc-archive-format.md](docs/pqc-archive-format.md#what-verification-actually-proves).

### Benchmarks

```bash
ics-pqc-evidence benchmark --output runtime/bench.json --csv runtime/bench.csv
```

Signed records are roughly **40× larger** than unsigned ones (about 4.9 KB versus 120 B), which is
usually the binding constraint on a Raspberry Pi rather than CPU time. See
[docs/pqc-benchmarks.md](docs/pqc-benchmarks.md).

### Further reading

| Document | Covers |
|---|---|
| [pqc-evidence-architecture.md](docs/pqc-evidence-architecture.md) | Design, module map, backend selection |
| [pqc-evidence-format.md](docs/pqc-evidence-format.md) | The envelope, canonical JSON, exactly what is signed |
| [pqc-key-management.md](docs/pqc-key-management.md) | Generate, register, rotate, revoke, compromise response |
| [pqc-threat-model.md](docs/pqc-threat-model.md) | What it protects against, and what it does not |
| [pqc-archive-format.md](docs/pqc-archive-format.md) | Archive container and validation rules |
| [pqc-benchmarks.md](docs/pqc-benchmarks.md) | Measured performance and Raspberry Pi guidance |

## Raspberry Pi deployment

The deployment script installs the fake PLC node as an **unprivileged user-level systemd unit** with
`NoNewPrivileges=true`. It never runs as root and never installs the controller:

```bash
scripts/deploy_rpi.sh --host 192.168.50.21 --user pi --modbus-host 192.168.50.10 --modbus-port 5020 --start
```

Install without starting the service:

```bash
scripts/deploy_rpi.sh --host 192.168.50.21 --dest /home/pi/ics-deception
```

Check on it afterwards:

```bash
ssh pi@192.168.50.21 'systemctl --user status ics-fake-plc'
```

Git metadata, virtualenvs, caches, logs and packet captures are excluded from the sync. Run
`sudo loginctl enable-linger pi` on the Pi if the unit must survive logout.

## Log locations

All runtime output lives under `runtime/` (override with `ICS_DECEPTION_RUNTIME_DIR`) and is
gitignored:

| Path | Contents |
|---|---|
| `runtime/events.jsonl` | Shared structured event bus for all Python components |
| `runtime/modbus_honeypot.jsonl` | Native Modbus honeypot events (`--log`) |
| `runtime/telnet_decoy.jsonl` | Telnet decoy events (`--log`) |
| `runtime/ssh_banner_decoy.jsonl` | SSH-banner decoy events (`--log`) |
| `runtime/components/<name>.log` | Child process stdout/stderr, one file per component |
| `runtime/replay.log` | Output of the most recent replay job |
| `runtime/plc_state.json` | Fake PLC's latest reading, written atomically |
| `runtime/pqc/evidence.jsonl` | Signed evidence records, when evidence sealing is enabled |
| `runtime/pqc/state.json` | Per-node chain state (sequence and last hash); **never delete this** |

Every event is one JSON object per line:

```json
{"timestamp":"2026-01-01T12:00:00.000000+00:00","source":"modbus_honeypot","event_type":"sabotage_detected","details":{"client_ip":"127.0.0.1","address":105,"alert":"write_to_critical_register"}}
```

## Security and ethical use

**Read [SECURITY.md](SECURITY.md) in full before deploying anything.** In short:

- **Authorized research only.** Use this only on systems and networks you own or have explicit
  written permission to test.
- **Never connect it to a production ICS or SCADA network.** Not to an operational segment, not to
  real field equipment, not to a network that routes to either.
- **Isolate the honeypots.** Put them on a segregated network with no credentials, secrets or trust
  relationships that matter anywhere else.
- **Run as an unprivileged user.** No component requires root. Forward port 502 rather than granting
  privileges.
- **Runtime logs contain attacker-supplied content.** Treat `runtime/` as untrusted input in any
  downstream parser, dashboard or shell pipeline.
- **Never commit packet captures.** They routinely contain addresses, credentials and process data.
- **PCAP replay produces active traffic.** It is not a simulation. Point it only at laboratory targets.
- **The controller has no authentication.** Do not expose it beyond loopback without an
  authenticating reverse proxy and network controls.
- **The DNP3 component is not a DNP3 implementation**, and **the SSH-banner component is not an SSH
  server**.
- **Never commit a private signing key.** Generate it on the node, keep it at mode `0600`, and let
  the deployment script's exclusions keep it off every other machine.
- **The evidence seal is not TLS** and does not encrypt any protocol traffic. It makes tampering
  with the *record* detectable; it does not prevent attacks or stop wholesale log deletion, and it
  makes no claim about legal chain of custody.

## Known limitations

- **Not standards compliant.** The Modbus honeypot implements five function codes over correct MBAP
  framing; diagnostics, file-record access, device identification and serial-gateway semantics are
  absent. It will not pass a conformance suite.
- **The DNP3 component is an interaction sensor, not an outstation.** No link-layer CRC validation,
  no transport segmentation, no application objects, no secure authentication. A real DNP3 master
  will not interoperate with it.
- **The SSH-banner decoy performs no SSH key exchange.** It emits an identification string and then
  speaks plain text. A real SSH client disconnects at key exchange. It captures scanner behaviour,
  not SSH sessions.
- **The Telnet decoy does not implement RFC 854 option negotiation.** IAC sequences are discarded.
- **Fingerprintable.** Timing, banners and the limited function-code coverage make these services
  distinguishable from real PLCs by a determined analyst.
- **No authentication or transport security anywhere.** Not on the controller, not in the event bus.
- **Single-host event bus.** `events.jsonl` is a local append-only file; there is no shipping,
  rotation, or central aggregation yet.
- **IPv4-only binding for the native services.** The C++ `--bind` option accepts IPv4 literals only;
  the PCAP analyser handles IPv6 addresses, but the honeypots do not bind them.
- **No persistence.** Register state is in memory and resets when a honeypot restarts.
- **Replay is stateless.** Payloads are replayed on fresh connections without reconstructing the
  original TCP sessions, so multi-frame transactions may not behave as they did in the capture.
- **Evidence signing multiplies log size by roughly 40×.** An ML-DSA-65 signature is 3309 bytes. On
  constrained nodes, sign selectively or in offline batches rather than signing every event.
- **A stolen node key forges evidence.** Signing is only as strong as the secrecy of the private
  key, and a honeypot is a machine you expect to be attacked. Rotation and revocation limit the
  window; they do not eliminate the risk.
- **The evidence seal cannot survive wholesale deletion.** It detects *selective* edits. An attacker
  with root can delete the whole log; ship evidence off the node if that matters.
- **The pure-Python PQC backend is not constant-time.** Prefer the native OpenSSL 3.5+ backend where
  timing side channels are a concern.
- **Truncation at the end of a log is undetectable.** There is no final marker on a live log; record
  the highest sequence seen elsewhere if that gap matters.
- **The native C++ services are not wired into the signing path.** `modbus_honeypot`, `fake_telnet`
  and `fake_ssh` write plain JSONL and are sealed after the fact with `sign-log`. Only the Python
  components sign as events occur.
- **Evidence sealing costs a synchronous signature per event.** In `sign`/`dual` mode every
  `publish()` performs an ML-DSA signature plus two `fsync`s before returning, which bounds event
  throughput. Measure with `ics-pqc-evidence benchmark` before enabling it on a busy node.
- **Recovery cannot restore lost records.** If the evidence log is truncated *after* state was
  committed, the signed records are gone; `recover-state` can only realign state with what survives,
  and the resulting gap stays visible as `pqc_sequence_gap`.

## Academic presentations

This work has been **presented at community conferences**:

- **FOSSCOMM 2024** — *"Lightweight IoT Honeypots for ICS Threat Deception & Monitoring"*
- **ECESCON 2025** — *"Deception-based Security Architecture for ICS Networks using IoT Honeypots"*

> **Note on status:** these were conference *presentations*. No claim is made that this work has been
> peer-reviewed or published in conference proceedings. If proceedings, DOIs or review records become
> available, they will be added here and to [CITATION.cff](CITATION.cff).

See [docs/experiments.md](docs/experiments.md) for the reproducible experiment protocols behind the
figures used in those talks.

## Roadmap

- [ ] S7comm and EtherNet/IP/CIP deception services
- [ ] Optional TLS and token authentication for the controller API
- [ ] Central event shipping (syslog / Kafka / OpenSearch) with log rotation
- [ ] Persistent register state and configurable process simulation profiles
- [ ] IPv6 binding for the native services
- [ ] Session-aware PCAP replay that reconstructs TCP transactions
- [ ] ESP32 port of the Modbus honeypot (removed in 0.2.0 as untestable in CI)
- [ ] Containerised laboratory topology with a reproducible compose file
- [ ] Published dataset of captured interactions
- [ ] Native `libcrypto` bindings for the OpenSSL backend, removing per-signature process spawn
- [ ] Signed chain-head publication, to close the log-truncation gap
- [ ] Multi-recipient evidence archives

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow,
coding standards and the required checks (`make check` must pass). Please read
[SECURITY.md](SECURITY.md) first, and report vulnerabilities privately rather than in a public issue.

## Citation

If this framework supports your research, please cite it using the metadata in
[CITATION.cff](CITATION.cff). GitHub renders it as a "Cite this repository" button.

## License

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
