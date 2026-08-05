# Experiment Protocols

Reproducible laboratory protocols for the framework. Each one states its objective, prerequisites,
exact commands, the events to look for, and how to analyse the result.

> **Before any experiment:** read [../SECURITY.md](../SECURITY.md). These protocols assume an
> **isolated laboratory network** with no path to production ICS equipment. Experiments E4 and E5
> generate real network traffic.

## Common setup

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
make install-dev
```

```bash
make build
```

Give each experiment its own runtime directory so datasets never mix:

```bash
export ICS_DECEPTION_RUNTIME_DIR="$PWD/runtime/E1-$(date +%Y%m%dT%H%M%S)"
```

A reusable one-liner for counting event types, used throughout:

```bash
python -c "import json,sys,collections;print(collections.Counter(json.loads(l)['event_type'] for l in open(sys.argv[1]) if l.strip()))" "$ICS_DECEPTION_RUNTIME_DIR/events.jsonl"
```

---

## E1 — Baseline: protocol correctness under fragmentation

**Objective.** Establish that the honeypot reassembles Modbus frames correctly regardless of how a
client segments them. This is the baseline every other experiment depends on.

**Hypothesis.** Response content is invariant to TCP segmentation: a request delivered in *n*
segments produces byte-identical output to the same request in one segment.

**Variables.** Independent: number of TCP writes per request (1, 2, 4, 12 = one byte at a time).
Dependent: response bytes, `modbus_request` event count.

### Procedure

1. Start the honeypot deterministically:

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --seed 1 --error-percent 0 --log "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

2. In another shell, drive it with the split-frame harness the test suite uses:

```bash
python -m pytest tests/test_modbus_integration.py -v
```

3. Record the results:

```bash
grep -c modbus_request "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

**Expected.** One `modbus_request` event per logical request regardless of segmentation, and
identical response bytes across all segmentation levels. Any deviation is a framing bug.

**Analysis.** Compare `bytes_in` in each `modbus_request` event against the frame length the client
sent. They must match exactly; a mismatch means the reassembly boundary is wrong.

---

## E2 — Critical-register sabotage detection

**Objective.** Measure whether writes to the simulated critical register range are reliably detected
and how quickly the alert is emitted.

**Hypothesis.** Every FC05/FC06/FC16 write touching `[crit-start, crit-end]` produces exactly one
`sabotage_detected` event, and writes outside the range produce none.

**Variables.** Independent: target register address, function code. Dependent: presence and count of
`sabotage_detected`; latency between the write and the log entry.

### Procedure

1. Start with an explicit critical range:

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --crit-start 100 --crit-end 110 --seed 1 --log "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

2. Sweep the register space, inside and outside the range:

```bash
python - <<'PY'
import socket
from ics_deception.common.modbus import build_write_single_register_request
for address in [50, 99, 100, 105, 110, 111, 200]:
    with socket.create_connection(("127.0.0.1", 5020), timeout=5) as s:
        s.sendall(build_write_single_register_request(1, 1, address, 0xC0DE))
        s.recv(256)
        print("wrote", address)
PY
```

3. Extract the alerts:

```bash
python -c "import json,sys;[print(json.loads(l)['details']['address']) for l in open(sys.argv[1]) if l.strip() and json.loads(l)['event_type']=='sabotage_detected']" "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

**Expected.** Alerts for exactly `100, 105, 110`. No alert for `50, 99, 111, 200`.

**Analysis.** Report as a confusion matrix over the address sweep. Detection is a pure range test, so
false positives or negatives indicate an off-by-one at a range boundary — which is why 99, 100, 110
and 111 are all sampled.

---

## E3 — Interaction profile of automated scanners

**Objective.** Characterise what unattended scanning traffic looks like across the deception surface.

**Hypothesis.** Automated scanners produce a distinctive, low-variety profile: short sessions, a
small set of default credentials, and few or no valid protocol requests.

**Variables.** Independent: exposure duration, service mix. Dependent: connections per hour, unique
source addresses, credential frequency distribution, function-code distribution, session duration.

### Procedure

1. Start the full surface on loopback (or on an isolated segment interface for real capture):

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --log "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

```bash
./build/fake_telnet --bind 127.0.0.1 --port 2323 --log "$ICS_DECEPTION_RUNTIME_DIR/telnet.jsonl"
```

```bash
./build/fake_ssh --bind 127.0.0.1 --port 2222 --log "$ICS_DECEPTION_RUNTIME_DIR/ssh.jsonl"
```

```bash
python -m ics_deception.honeypots.dnp3_sensor --host 127.0.0.1 --port 20000
```

2. Run for a defined observation window (24 h, 7 d — state it in your results).

3. Aggregate:

```bash
python -c "import json,glob,collections;c=collections.Counter(json.loads(l)['event_type'] for f in glob.glob('$ICS_DECEPTION_RUNTIME_DIR/*.jsonl') for l in open(f) if l.strip());print(c.most_common())"
```

**Expected.** `login_attempt` events dominated by a handful of usernames; `password_length` clustering
at short values; Modbus traffic dominated by FC03 reads.

> **Credential policy.** Passwords are **not** stored by default — only length and character-class
> shape. Enable `--capture-credentials` only under a documented retention and destruction plan, and
> record that decision in your results. See [../SECURITY.md](../SECURITY.md).

**Analysis.** Report connections/hour, unique sources, top 10 usernames, the `password_length`
histogram, and the function-code distribution. Cross-reference source addresses against a public
scanner list to separate background noise from targeted interaction.

---

## E4 — Latency and error-injection realism

**Objective.** Determine whether simulated response latency and error rates change how long an
attacker engages.

⚠️ **Generates active traffic.** Isolated laboratory only.

**Hypothesis.** Response latency within a plausible PLC envelope (10–150 ms) does not reduce
engagement, whereas a high exception rate does.

**Variables.** Independent: `--min-latency-ms`/`--max-latency-ms`, `--error-percent`. Dependent:
session duration, requests per session, reconnection count.

### Procedure

Run each arm for an equal observation window, changing exactly one variable at a time. Always fix
`--seed` so the run is reproducible.

Control — instant, never fails:

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --seed 42 --error-percent 0 --log "$ICS_DECEPTION_RUNTIME_DIR/arm-control.jsonl"
```

Arm A — realistic PLC latency:

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --seed 42 --min-latency-ms 10 --max-latency-ms 150 --error-percent 0 --log "$ICS_DECEPTION_RUNTIME_DIR/arm-latency.jsonl"
```

Arm B — degraded device:

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --seed 42 --min-latency-ms 10 --max-latency-ms 150 --error-percent 15 --log "$ICS_DECEPTION_RUNTIME_DIR/arm-degraded.jsonl"
```

**Expected.** Comparable engagement between control and Arm A; measurably shorter sessions in Arm B.

**Analysis.** For each arm compute session duration from `connection` to `connection_closed` per
client, and requests per session. Compare distributions with a Mann–Whitney U test — session
durations are not normally distributed, so a t-test is the wrong tool. Report effect size, not just
a p-value.

> **Note.** Error injection defaults to `0` precisely so that E1, E2 and the test suite stay
> deterministic. Only enable it inside this experiment.

---

## E5 — Replaying captured ICS traffic

**Objective.** Validate that the honeypot responds plausibly to traffic recorded from real (or
simulated) ICS equipment.

⚠️ **`--replay` transmits real traffic.** Verify your target address before running it.

**Hypothesis.** A capture of legitimate Modbus polling elicits well-formed responses with no
malformed-frame events, demonstrating that the deception surface is adequate for observed field
traffic.

### Procedure

1. Place the capture in the approved directory (never commit it):

```bash
cp /path/to/capture.pcap data/pcaps/
```

2. Analyse passively first — this transmits nothing:

```bash
python -m ics_deception.datasets.pcap_loader --pcap data/pcaps/capture.pcap
```

3. Start the honeypot as the replay target:

```bash
./build/modbus_honeypot --bind 127.0.0.1 --port 5020 --seed 1 --error-percent 0 --log "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

4. Replay against it, bounded:

```bash
python -m ics_deception.datasets.pcap_loader --pcap data/pcaps/capture.pcap --replay --modbus-target 127.0.0.1:5020 --max-packets 500
```

5. Compare the passive counters against what the honeypot recorded:

```bash
grep -c modbus_request "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

```bash
grep -c modbus_malformed "$ICS_DECEPTION_RUNTIME_DIR/modbus.jsonl"
```

**Expected.** `packets_replayed` from the loader roughly matches `modbus_request` at the honeypot;
`modbus_malformed` is zero for a clean capture.

**Analysis.** Any exception responses identify function codes the honeypot does not cover — that
list is the concrete backlog for improving the deception surface. Note that replay is *stateless*:
each payload goes out on a fresh connection, so multi-frame transactions from the capture will not
behave identically.

---

## Reporting checklist

For every experiment, record:

- [ ] Commit hash (`git rev-parse --short HEAD`) and framework version
- [ ] Exact command lines, including every flag and the `--seed`
- [ ] Host OS, kernel, Python and compiler versions
- [ ] Network topology and the isolation measures in force
- [ ] Observation window with start and end timestamps
- [ ] Raw JSONL event counts per type
- [ ] Whether credential capture was enabled, and the retention plan if so
- [ ] Any deviation from the protocol above

Archive the raw JSONL alongside the analysis. **Redact source addresses and any captured credentials
before publication**, and never publish a raw capture.
