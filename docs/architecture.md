# Architecture

This document describes how the ICS Deception Framework is put together and why. For the security
rationale behind these choices see [threat-model.md](threat-model.md).

## Design goals

1. **Believable enough, honest about it.** Services must respond correctly enough that an attacker
   engages, while the documentation never overstates protocol conformance.
2. **One telemetry stream.** Every component — Python or C++ — emits the same JSONL event schema, so
   a distributed deployment produces a single analysable artifact.
3. **Safe by default.** Loopback binding, unprivileged ports, no root, nothing autostarted, no
   plaintext credential storage, no random behaviour unless requested.
4. **Cheap edge nodes.** The deception nodes must run on Raspberry Pi class hardware, so the C++
   services have no external dependencies and the Python services lean on the standard library.
5. **Testable.** Every protocol behaviour is reachable from a test on an unprivileged loopback port.

## Component map

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE (loopback)                        │
│                                                                          │
│  ics_deception.controller                                                │
│  ├── config.py    Pydantic-validated JSON; per-component enable/autostart│
│  ├── process.py   Supervision: process groups, log redirection, teardown │
│  ├── app.py       FastAPI: /health /status /logs /ics-values             │
│  │                         /components/{name}/start|stop /replay         │
│  └── cli.py       Entry point; warns on non-loopback binding             │
└───────────────┬──────────────────────────────────────────────────────────┘
                │ spawns (own process group, stdout → runtime/components/*.log)
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                            DECEPTION PLANE                               │
│                                                                          │
│  src/native/modbus_honeypot.cpp    C++17  TCP/5020  FC01/03/05/06/16     │
│  src/native/fake_telnet.cpp        C++17  TCP/2323  fake RTU shell       │
│  src/native/fake_ssh.cpp           C++17  TCP/2222  SSH banner + shell   │
│  honeypots/modbus_server.py        Python TCP/5020  FC03/FC06 subset     │
│  honeypots/dnp3_sensor.py          Python TCP/20000 interaction sensor   │
│  iot_nodes/fake_plc.py             Python client    FC03 poller          │
└───────────────┬──────────────────────────────────────────────────────────┘
                │ append-only JSONL
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                            TELEMETRY PLANE                               │
│                                                                          │
│  runtime/events.jsonl              shared Python event bus               │
│  runtime/*.jsonl                   native service logs                   │
│  runtime/components/<name>.log     child stdout/stderr                   │
│  runtime/plc_state.json            fake PLC snapshot (atomic writes)     │
└───────────────┬──────────────────────────────────────────────────────────┘
                │ read
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                             ANALYSIS PLANE                               │
│                                                                          │
│  datasets/pcap_loader.py   streaming analysis (default) / replay (opt-in)│
│  datasets/pcap_utils.py    path validation, HOST:PORT parsing            │
└──────────────────────────────────────────────────────────────────────────┘
```

## The event schema

Every event, from either language, is one JSON object per line:

```json
{
  "timestamp": "2026-01-01T12:00:00.000000+00:00",
  "source": "modbus_honeypot",
  "event_type": "sabotage_detected",
  "details": {"client_ip": "127.0.0.1", "client_port": 51544, "address": 105}
}
```

`details` is free-form per event type. Values are truncated (`MAX_DETAIL_STRING`, 512 characters in
Python) and the C++ logger escapes control characters as `\uXXXX`, so a peer cannot inject a
newline and forge a second event.

The Python side is `EventPublisher`, whose class-level lock serialises writes across every publisher
instance in the process. The C++ side is `icsd::JsonLogger`, a mutex-guarded appender that also
mirrors each line to stdout — which the controller captures into the component's log file.

### Obtaining a publisher

Python components never construct `EventPublisher` directly. They call
`ics_deception.common.publisher.create_event_publisher(source, log_path=None, echo=True)`, which
reads the `ICS_PQC_*` environment and returns either a plain publisher or one with an evidence sink
attached. Two consequences worth knowing:

* **Evidence sealing is a deployment decision, not a code change.** The same binary signs or does
  not sign depending on `ICS_PQC_EVIDENCE_MODE`.
* **A node without the PQC extras still starts.** `pqc_evidence` is imported lazily inside the
  factory, so `pip install .` without `[pqc]` runs the honeypots normally; only an explicit request
  to seal evidence fails, and it fails with a message naming what to install.

The factory shares one evidence sink per process, so several publishers on one node contribute to a
single chain rather than competing for the lock. `evidence_status()` reports the active mode,
backend and metrics; `reset_shared_sink()` exists for tests.

The C++ components do not use this path — see the signing-coverage table in the README.

### Core event types

| Source | Events |
|---|---|
| Modbus (both) | `connection`, `connection_closed`, `modbus_request`, `modbus_response`, `modbus_malformed`, `modbus_timeout`, `modbus_connection_error`, `sabotage_detected`, `connection_rejected` |
| DNP3 sensor | `dnp3_connection`, `dnp3_interaction`, `dnp3_timeout`, `dnp3_session_limit`, `dnp3_connection_closed` |
| Decoys | `*_connection`, `login_attempt`, `*_command`, `*_timeout`, `*_line_too_long`, `*_command_limit`, `*_connection_closed` |
| Fake PLC | `fake_plc_startup`, `fake_plc_poll`, `fake_plc_poll_failed` |
| Controller | `controller_startup`, `controller_shutdown`, `component_started`, `component_stopped`, `component_start_failed`, `replay_requested`, `replay_started`, `replay_finished` |
| PCAP | `pcap_analysis_started`, `modbus_packet`, `dnp3_packet`, `*_replayed`, `*_replay_error`, `pcap_analysis_finished` |

## Modbus/TCP framing

The single most important mechanism in the project. TCP is a byte stream: one `recv()` may return
half a request, or three of them. The MBAP header's length field is what makes correct framing
possible.

```
byte:  0   1   2   3   4   5   6   7 ...
      ┌───────┬───────┬───────┬───┬─────────────┐
      │ txn   │ proto │ len   │uid│ PDU         │
      └───────┴───────┴───────┴───┴─────────────┘
        2       2       2       1   len-1

      total frame = 6 + len
```

Both the C++ and Python servers run the same loop:

```
buffer ← buffer + recv()
while buffer holds ≥ 7 bytes:
    validate protocol_id == 0                → else log malformed, drop connection
    validate 2 ≤ length ≤ 254                → else log malformed, drop connection
    frame_len ← 6 + length
    if len(buffer) < frame_len: break            # partial frame, await more bytes
    frame ← buffer[0:frame_len]; consume it
    dispatch(frame) and reply
if len(buffer) > MAX_BUFFER: log overflow, drop  # bounded memory
```

That single loop delivers three required behaviours at once: split requests are reassembled,
pipelined requests are all serviced, and a peer cannot exhaust memory by dribbling bytes.

Validation happens in strict order — protocol identifier, declared length, then function-specific
PDU length, then addresses, quantities, values and byte counts — so an out-of-range field is never
used as an index. Exception responses are built from scratch at exactly 9 bytes; no byte of a
malformed request is ever reflected back.

## Process supervision

`ManagedProcess` embodies four decisions worth stating explicitly:

- **Log files, not pipes.** `stdout=<file>` rather than `subprocess.PIPE`. An unread pipe fills its
  OS buffer (typically 64 KiB) and blocks the child forever — the original prototype's most likely
  hang.
- **Own process group.** `start_new_session=True` on POSIX. A service that forks helpers can then be
  signalled as a unit via `os.killpg`, and a Ctrl-C aimed at the controller does not reach children.
- **`sys.executable`.** Python components run under the interpreter running the controller, so a
  virtual environment is honoured instead of whatever `python3` resolves to on `PATH`.
- **Validate before spawn.** A relative `binary` path is resolved against the project root, checked
  for containment, existence and the executable bit *before* `Popen`. Failures are captured in
  `last_error` and reported through `/status`; they never propagate and kill the controller.

Shutdown escalates `SIGTERM` → wait 5 s → `SIGKILL`, against the process group.

## Replay safety

`POST /replay` applies five independent controls:

1. **Extension allowlist** — `.pcap` and `.pcapng` only.
2. **Resolve, then contain** — `Path.resolve()` collapses `..` and follows symlinks *before*
   containment against the approved directory is tested. Resolving first is what makes both
   traversal and symlink escapes detectable.
3. **Existence and file-type check** — must be a regular file.
4. **Packet budget** — the request's `max_packets` is clamped to the configured maximum.
5. **Single-job lock** — a second concurrent request gets `409 Conflict`.

Status codes are distinct by failure mode (`400` extension, `403` traversal, `404` missing, `409`
busy) so a caller can tell what went wrong.

Replay itself only transmits **client-to-server** payloads, identified by comparing the TCP
destination port against the service port. Replaying server responses would send PLC replies at a
PLC, which is meaningless and potentially harmful.

## Runtime path resolution

All mutable state resolves through `ics_deception.common.paths`, which reads its environment
variables **at call time** rather than at import. That is what lets the test suite redirect every
path into a `tmp_path` with `monkeypatch.setenv`, and lets a deployment relocate state with a single
variable. No directory is created at import; creation is lazy, at first write.

## Atomic state publication

The fake PLC and the controller are separate processes sharing `plc_state.json`. A naive
`open(path, "w")` truncates the file, so a reader can observe an empty or half-written document.
`write_state_atomically` instead writes a temporary file **in the same directory**, `fsync`s it, and
calls `os.replace`. A same-filesystem rename is atomic on POSIX and on Windows, so a reader sees
either the whole old file or the whole new one — never a partial one.

## Concurrency model

| Component | Model | Bound |
|---|---|---|
| C++ services | one detached `std::thread` per client | `--max-clients` (default 16), atomic counter |
| Python servers | `ThreadingTCPServer`, daemon threads | OS limits; per-client receive timeouts |
| Controller | uvicorn event loop; supervision under an `RLock` | one replay job at a time |

Every listener sets `SO_RCVTIMEO`, so a silent peer releases its slot rather than holding a thread
indefinitely.

## Deliberate non-goals

- **No protocol conformance.** These are deception surfaces. Implementing DNP3 properly would mean
  link-layer CRCs, transport segmentation, application objects and secure authentication — a project
  in its own right.
- **No distributed control plane.** One controller supervises local processes. Multi-site
  aggregation is a roadmap item.
- **No persistence.** Register state lives in memory and resets on restart. Deception value comes
  from the interaction record, not from durable process state.
- **No evasion.** No attempt is made to defeat honeypot fingerprinting.
