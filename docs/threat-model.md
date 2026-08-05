# Threat Model

Scope: the ICS Deception Framework as deployed in an **isolated laboratory** for authorized
research. This is not a threat model for an operational ICS environment, and the framework must
never be attached to one.

A honeypot is unusual: it *invites* attack. The question is never "can it be attacked" but "what
happens when it is, and what can the attacker reach from there".

## Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | Interaction telemetry (`runtime/*.jsonl`) | The entire research output. Loss or forgery invalidates results. |
| A2 | Host running the deception services | Compromise gives a foothold and a launch point against third parties. |
| A3 | The laboratory network | Lateral movement from a honeypot to anything that matters is the worst case. |
| A4 | Packet captures in `data/pcaps/` | May contain real addresses, credentials and process data. |
| A5 | Captured credentials (opt-in only) | Frequently real, reused, third-party credentials. Legal exposure. |
| A6 | Controller API | Spawns processes and generates network traffic. |
| A7 | The repository itself | A leaked capture, log or key is permanent once pushed publicly. |

## Trust boundaries

```
   UNTRUSTED                        │ SEMI-TRUSTED            │ TRUSTED
   ─────────────────────────────────┼─────────────────────────┼──────────────────
   Attacker / scanner traffic  ─────▶ Deception services      │
   Captured PCAP payloads      ─────▶ PCAP analyser           │
   Log content (once written)  ─────▶ Downstream parsers      │
                                     │                        │
                                     │ Controller API   ──────▶ Local operator
                                     │ (loopback, no auth)    │ Configuration files
                                     │                        │ Repository contents
```

**B1 — network → deception service.** Every byte is attacker-controlled. This is the primary attack
surface and where the C++ parsing code lives.

**B2 — service → event log.** Attacker-influenced data crosses into stored form. Truncation and
escaping happen here.

**B3 — event log → downstream consumer.** Anything reading the log (dashboard, SIEM, script) is
consuming untrusted data.

**B4 — HTTP client → controller.** No authentication. Loopback binding *is* the control.

**B5 — capture file → replay.** A capture is untrusted input that becomes transmitted traffic.

**B6 — developer → repository.** The boundary where a capture or secret becomes permanently public.

## Adversaries

| ID | Adversary | Capability | Goal |
|---|---|---|---|
| T1 | Opportunistic scanner | Mass internet scanning, default credentials | Enumerate, add to a botnet |
| T2 | ICS-aware attacker | Modbus/DNP3 tooling, protocol knowledge | Map the process, write registers, manipulate |
| T3 | Honeypot-aware attacker | Fingerprinting, anti-analysis | Identify deception, poison the dataset, escape the host |
| T4 | Malicious capture supplier | Crafts a PCAP for someone else to analyse | Exploit the analyser or force unwanted traffic |
| T5 | Careless insider | Repository write access | Accidentally commit a capture, log or key |

## Threats and mitigations

### B1 — network to deception service

| ID | Threat | Adversary | Mitigation | Residual |
|---|---|---|---|---|
| TH-01 | Memory corruption via crafted Modbus frame | T2, T3 | Every length validated before indexing; `std::vector` bounds; frame ≤ 260 B; PDU length checked exactly per function code | Low — C++ still permits logic errors |
| TH-02 | Memory exhaustion by dribbling partial frames | T1–T3 | Reassembly buffer capped at `4 × MAX_ADU`; overflow logs and drops | Low |
| TH-03 | Thread exhaustion / slowloris | T1, T3 | `--max-clients` cap; `SO_RCVTIMEO` on every socket; excess connections rejected and logged | Medium — a distributed flood still saturates the cap |
| TH-04 | Crash by malformed frame → denial of the sensor | T3 | Malformed input is logged and the connection dropped; the accept loop continues; thread-spawn failure is caught | Low |
| TH-05 | Unbounded input on the interactive decoys | T1 | Line length capped (512), commands per session capped (200), session bytes capped | Low |
| TH-06 | Privilege escalation from a service | T2, T3 | No component needs root; unprivileged ports; systemd `NoNewPrivileges=true`, `ProtectSystem=full`, `RestrictSUIDSGID=true` | Medium — a kernel bug still escapes |
| TH-07 | Host compromise → lateral movement | T2, T3 | Network isolation, no valuable credentials on the host, egress filtering | **High if isolation is not enforced.** This is the dominant risk. |

### B2/B3 — log integrity and downstream injection

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| TH-08 | Forged log lines via embedded newlines | JSON-escaped output; C++ logger encodes control chars as `\uXXXX`; one object per line | Low |
| TH-09 | Log inflation to fill the disk | Detail values truncated to 512 chars; payload samples bounded to 32 bytes | Medium — event *count* is unbounded; operator must rotate |
| TH-10 | Stored XSS / command injection in a downstream consumer | Documented as untrusted input in SECURITY.md | **Consumer's responsibility** — outside this codebase |
| TH-11 | Log tampering after the fact | None in-tree | High — use external append-only shipping if integrity matters |

### B4 — controller API

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| TH-12 | Unauthenticated process spawning | Loopback default; components disabled by default; `409` for disabled; argv validated, never `shell=True` | **High if bound to a non-loopback address.** A stderr warning is emitted. |
| TH-13 | Arbitrary path read via replay | Extension allowlist → resolve → containment → existence, in that order | Low |
| TH-14 | Command injection through configuration | Pydantic model with `extra: forbid`; argv is a list, never a shell string; relative executables must resolve inside the project root | Low — an operator with write access to the config already controls the host |
| TH-15 | Resource exhaustion by repeated replay | One job at a time (`409`); packet budget clamped | Low |
| TH-16 | Child process blocks on a full pipe | stdout/stderr redirected to files, never `PIPE` | Resolved |

### B5 — capture handling and replay

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| TH-17 | Malicious PCAP exploits the parser | Scapy is the parsing surface; only bounded metadata extracted; no payload evaluation | Medium — inherited from Scapy |
| TH-18 | Memory exhaustion from a huge capture | Streaming `PcapReader`; `--max-packets` | Low |
| TH-19 | Replay hits an unintended host | Targets are explicit CLI/API parameters, never inferred from the capture; a stderr warning names them; only client-to-server payloads | Medium — an operator can still type a wrong address |
| TH-20 | Replay causes real process actuation | Documented prohibition on connecting to production ICS | **High if the prohibition is ignored.** No technical control can prevent this. |

### B6 — repository hygiene

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| TH-21 | Capture or log committed publicly | `.gitignore` covers `*.pcap`, `*.pcapng`, `*.jsonl`, `*.log`, `runtime/`; CI fails if such a file is tracked; upload checklist | Low |
| TH-22 | Secrets committed | `.env` ignored, only `.env.example` tracked; checklist greps for key patterns | Medium — no automated pre-commit secret scan yet |
| TH-23 | Captured credentials mishandled | Off by default; only length and character-class shape logged; opt-in flag recorded in the event | Medium — enabling it is an operator decision |

## Accepted risks

These are conscious decisions, not oversights.

1. **The services are fingerprintable.** Limited function-code coverage, static banners and timing
   characteristics identify them to a determined analyst. Countering this is a research problem of
   its own and is out of scope for a lightweight prototype.
2. **No authentication or transport security.** The controller relies on loopback binding. Adding
   TLS and tokens is on the roadmap.
3. **No log rotation or shipping.** `events.jsonl` grows without bound. The operator must cap it.
4. **No persistence.** Register state resets on restart, so a long-running manipulation is not
   preserved across a crash.
5. **Replay is stateless.** Payloads go out on fresh connections without reconstructing the original
   TCP sessions, so multi-frame transactions may behave differently than in the capture.

## The controlling assumption

Every mitigation above is secondary to one thing:

> **The deception fabric is deployed on an isolated laboratory network with no path to production
> ICS, no valuable credentials, and no trust relationships that matter elsewhere.**

If that assumption holds, the worst realistic outcome is the loss of a disposable host and a
poisoned dataset. If it does not hold, none of the technical controls in this project are sufficient,
because the framework's entire purpose is to attract skilled attackers and let them interact.
