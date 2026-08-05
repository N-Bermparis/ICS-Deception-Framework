# Security Policy

## Intended use

The ICS Deception Framework is a **research prototype for authorized laboratory use only**. It
exists so that researchers can study how adversaries interact with industrial protocol services in a
controlled environment.

Use it only on systems and networks that you own, or for which you hold **explicit written
authorization** to conduct security testing. Deploying deception services on infrastructure you do
not control may be unlawful in your jurisdiction regardless of intent.

## Hard requirements

These are not recommendations. Violating any of them can cause real physical or operational harm.

### Never connect this to a production ICS or SCADA network

Not to an operational segment. Not to real field equipment, PLCs, RTUs or safety systems. Not to any
network that routes to them. A honeypot that answers Modbus writes on a live process network can
confuse legitimate masters, corrupt historian data, or mask a genuine device.

### Isolate the deception fabric

Place the honeypots on a **segregated network** with:

- no routes to operational technology or corporate networks,
- no credentials, keys, certificates or tokens that are valid anywhere else,
- no trust relationships (domain join, SSH agent forwarding, shared NFS) with anything sensitive,
- egress filtering, so a compromised node cannot be used to attack third parties.

Treat every honeypot host as though it will eventually be compromised, because the entire point is
to attract people who try.

### Run as an unprivileged user

No component in this project requires root.

- All services bind to **loopback** by default and use **unprivileged ports** (5020, 20000, 2323,
  2222, 8000).
- Do **not** run a honeypot as root just to bind port 502. Keep it on 5020 and redirect at the
  firewall (see the README), or grant `CAP_NET_BIND_SERVICE` to that one binary if you must.
- The Raspberry Pi deployment installs a **user-level** systemd unit with `NoNewPrivileges=true` and
  refuses to run as root.

### Runtime logs contain attacker-supplied data

Everything under `runtime/` — `events.jsonl`, the native `*.jsonl` logs, per-component logs — records
data controlled by whoever connected. Values are truncated and JSON-escaped, and control characters
in the C++ logger are emitted as `\uXXXX`, so a peer cannot forge log lines. That is **not** the same
as the content being safe.

- Never `eval`, `source`, or interpolate log content into a shell command.
- Assume any downstream dashboard is exposed to stored XSS unless it escapes on output.
- Treat the logs as evidence: restrict read access and preserve integrity if an incident matters.

### Never commit packet captures

Captures routinely contain internal addressing, device identifiers, credentials and live process
values. `*.pcap`, `*.pcapng` and `*.cap` are gitignored, and `data/pcaps/` keeps only a `.gitkeep`.
Verify with `git status` before every commit. CI fails the build if a capture, log or binary is
tracked.

### PCAP replay transmits real traffic

`--replay` is not a simulation. It opens TCP connections and sends captured payloads to the hosts
you name. Only client-to-server payloads are replayed and the packet count is bounded, but the
traffic is real. Point it exclusively at laboratory targets you control, and never at an address you
have not verified.

### The controller has no authentication

`GET /logs` exposes attacker data, `POST /components/{name}/start` spawns processes and `POST
/replay` generates network traffic. There is **no authentication, authorization, CSRF protection or
transport security**.

- It binds to `127.0.0.1` by default. Keep it there.
- If remote access is genuinely required, put it behind an authenticating reverse proxy on an
  isolated management network, and restrict source addresses at the firewall.
- The controller emits a warning to stderr when configured to bind a non-loopback address.

### Credentials captured by the decoys

The Telnet and SSH-banner decoys **do not store plaintext passwords by default**. They log the
username, the password *length*, and a coarse character-class shape (e.g. `aA0`). Plaintext capture
requires the explicit `--capture-credentials` flag.

Only enable it for a controlled experiment with a defined retention and destruction plan. Captured
credentials are frequently reused real credentials belonging to third parties, and handling them may
carry legal obligations.

## Post-quantum evidence sealing

The optional `pqc_evidence` layer signs honeypot logs so that later tampering becomes detectable.
Be precise about what that buys you.

**It is not TLS.** It is not a secure channel of any kind, it does not encrypt Modbus or DNP3
traffic, and it has no bearing on what an attacker can see on the wire. Transport security is
maintained as a separate project.

**It does not prevent attacks.** It makes edits to the *record* of an attack detectable, after the
fact.

**It does not survive wholesale deletion.** An attacker with root on a node can delete the entire
evidence log and its state file. Selective edits — changing a value, dropping one event, reordering
two — are what become detectable. Ship evidence off the node if that distinction matters to you.

**It does not guarantee legal chain of custody.** It is a tamper-evident technical mechanism. No
claim is made about evidentiary standing in any jurisdiction.

**It proves provenance, not truth.** If a honeypot records something incorrectly, the signature
faithfully attests to the incorrect record.

**Not every component signs as events happen.** The Python services sign and persist each event
before `publish()` returns. The native C++ `modbus_honeypot`, `fake_telnet` and `fake_ssh` binaries
contain no cryptographic code — they write plain JSONL that is sealed afterwards with `sign-log`.
Anything written in that interval can still be altered before it is signed. Do not describe native
honeypot events as signed in real time, because they are not.

### What the transaction guarantees

Signing and persistence are one transaction under one lock, so evidence sealing does not introduce
its own integrity gaps:

- A sequence number is issued at most once, enforced across processes by an advisory lock with a
  bounded timeout.
- Records appear in the file in sequence order, because the append happens inside the lock hold that
  allocated the sequence.
- A crash at any point leaves a consistent chain: a fully written record is committed on restart, a
  partial one is rolled back and its bytes preserved (mode `0600`) for inspection.

What it deliberately does **not** do is invent replacements for evidence that was destroyed after
being committed. That condition halts signing with `EvidenceStateDivergence` and requires an
operator to run `ics-pqc-evidence recover-state --confirm`. Treat that error as an incident signal,
not as noise to be cleared.

### Verifying an archive is not the same as trusting it

Decrypting an archive proves it was sealed to you and its manifest is intact. It proves nothing
about the enclosed events, because whoever built the archive also wrote its manifest. Only
`verify-archive --registry <trusted public keys>` can report `fully_verified`; without a registry the
tool warns that the enclosed evidence was not verified. Do not treat a zero exit code from the
container-only check as evidence verification.

### Key handling rules

- **Generate a private key on the node that will use it.** Never copy one between machines.
- **Never commit a private key.** `keys/`, `*.key`, `*.pem` and `*.pqcarch` are gitignored, the
  deployment script excludes them from every sync, and CI fails if one is ever tracked.
- Private keys are written mode `0600`; loading a group- or world-readable key is **refused**.
- The key generator refuses to overwrite an existing private key.
- Public test fixtures, where they exist, are **public-only** and clearly labelled.
- Keys produced by the `insecure-test-only` backend carry the literal marker
  `INSECURE-TEST-ONLY-KEY-DO-NOT-USE`, are never selected automatically, and are refused entirely
  when `ICS_PQC_PRODUCTION=1`.

### No classical fallback

If ML-DSA is unavailable, signing **fails with a structured error**. It never silently falls back to
RSA, ECDSA, Ed25519, HMAC or a mock signature. A log that looks signed but is not would be worse
than an unsigned one.

### Archive keys

The ML-KEM-768 archive key is separate from the node signing key and belongs to the analyst, not the
node. Back it up: losing it makes archives permanently unreadable, by design.

See [docs/pqc-threat-model.md](docs/pqc-threat-model.md) for the full analysis and
[docs/pqc-key-management.md](docs/pqc-key-management.md) for procedures.

## Protocol implementation honesty

Do not rely on these services being protocol-correct — they are deception surfaces, not stacks.

- **The Modbus honeypot is not standards compliant.** It implements FC01, FC03, FC05, FC06 and FC16
  over correct MBAP framing. Diagnostics, file-record access, device identification and
  serial-gateway behaviour are absent.
- **The DNP3 component is not a DNP3 outstation.** No link-layer CRC validation, no transport
  segmentation, no application-layer objects, no secure authentication. It is an *interaction
  sensor*.
- **The SSH-banner component is not an SSH server.** It performs no key exchange and no encryption.
  A real SSH client will disconnect. Anything it captures came from a scanner, not an SSH session.
- **The Telnet decoy does not implement RFC 854** option negotiation.

## Known residual risks

| Risk | Status |
|---|---|
| Services are fingerprintable as honeypots | Accepted; inherent to a lightweight prototype |
| No authentication on the controller API | Mitigated only by loopback binding |
| No transport encryption anywhere | Accepted for isolated laboratory use |
| Event log grows without rotation | Accepted; operator must rotate or cap disk |
| Replay can generate substantial traffic | Mitigated by `--max-packets` and single-job locking |
| Compromise of a honeypot host | Mitigated by isolation, unprivileged execution, systemd hardening |
| A decoy thread can be tied up by a slow peer | Mitigated by receive timeouts and client limits |
| A stolen node signing key forges evidence | Mitigated only by rotation and revocation; **high** on a compromised node |
| Wholesale deletion of an evidence log | Not detectable locally; ship evidence off the node |
| Truncation at the end of an evidence log | Not detectable; no final marker exists on a live log |
| Evidence logs are not confidential | Signing does not encrypt; use archives when confidentiality is needed |
| Native C++ honeypot events are sealed after the fact, not as they occur | Accepted; the binaries carry no crypto. Run `sign-log` often, or capture through a Python service |
| Evidence destroyed after its state was committed cannot be recovered | Halts signing with `EvidenceStateDivergence` and requires an explicit operator repair; the gap stays visible |
| Signing adds a synchronous ML-DSA signature and two `fsync`s per event | Accepted; measure with `ics-pqc-evidence benchmark` before enabling on a busy node |

See [docs/threat-model.md](docs/threat-model.md) for the full analysis.

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue for a vulnerability.

1. Use GitHub's **Report a vulnerability** button under the repository's Security tab (private
   vulnerability reporting), or contact the maintainers directly through the repository's
   security contact.
2. Include affected version or commit, reproduction steps, impact, and any suggested fix.
3. Please allow up to 90 days for a fix before public disclosure.

Expected response times, on a best-effort basis for a research project:

| Stage | Target |
|---|---|
| Acknowledgement | 7 days |
| Initial assessment | 14 days |
| Fix or documented mitigation | 90 days |

### Scope

**In scope:** memory-safety or crash bugs in the C++ services; parsing flaws reachable from the
network; path traversal or command injection in the controller; privilege escalation in the
deployment script; unintended credential or capture disclosure; **any way to make the evidence
verifier accept tampered, forged or replayed evidence**; private key disclosure through logs,
reports, archives or benchmark output; sequence reuse in the signer; **any way to make the
transactional store lose, reorder or duplicate a committed record, or to make an archive report
`fully_verified` without the enclosed evidence having been checked against a trusted key**.

**Out of scope:** the fact that services are fingerprintable as honeypots; the documented absence of
authentication on the loopback controller; the documented protocol incompleteness; anything
requiring a configuration the documentation explicitly warns against.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x (0.3.0b1, beta) | ✅ Current development line |
| 0.2.x | ❌ Superseded; no fixes |
| 0.1.x | ❌ Superseded; no fixes |

As an alpha research prototype, only the latest development line receives fixes.
