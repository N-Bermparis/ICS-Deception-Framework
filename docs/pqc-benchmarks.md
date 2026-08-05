# PQC Benchmarks

How to measure what post-quantum evidence signing costs on *your* hardware, and what it cost on
ours. The point is not to publish flattering numbers — it is to let you decide whether a Raspberry
Pi can afford to sign every event, or only the interesting ones.

## Running a benchmark

```bash
ics-pqc-evidence benchmark --output runtime/bench.json --csv runtime/bench.csv
```

Options:

```bash
ics-pqc-evidence benchmark --backend pyfips --iterations 50 --chain-events 500 --output runtime/bench.json
```

| Option | Meaning |
|---|---|
| `--backend` | Force `openssl` or `pyfips`; default is the preferred available backend |
| `--iterations` | Repetitions per primitive (must be > 0; default 20) |
| `--chain-events` | Events in the signed-log and verification tests (must be > 0; default 200) |
| `--no-archive` | Skip the ML-KEM and archive measurements |
| `--output` | Write the JSON report |
| `--csv` | Also write measurements as CSV |

Each measurement runs one untimed warm-up first, so lazy imports and table construction do not
pollute a short run.

## What is measured

* ML-DSA-65 key generation, signing and verification latency, plus operations per second
* Signature, public key and private key sizes
* ML-KEM-768 key generation, encapsulation and decapsulation
* Archive creation and decryption time, and AES-GCM overhead
* Signed-log throughput and the **storage overhead versus unsigned JSONL**
* Chain verification throughput
* Peak RSS and CPU time
* Full environment: platform, CPU model, core count, Python version, OpenSSL version, backend and
  provider details, and the exact parameters used

## Results are safe to share

The report contains **no key material**: keys are generated in memory, never written, and never
serialised into the output. Only *sizes* appear. The hostname field is deliberately left empty. A
test asserts that no `-----BEGIN` block ever reaches the report.

## Reference results

**Machine:** Intel Core Ultra 9 275HX, 24 cores, Linux 6.6 (WSL2), Python 3.10.12.
**Parameters:** `--iterations 15 --chain-events 100`.

### Native OpenSSL backend (OpenSSL 3.5.0)

| Operation | Mean | Ops/s |
|---|---|---|
| ML-DSA-65 keygen | 7.52 ms | 133 |
| ML-DSA-65 sign | 7.28 ms | 137 |
| ML-DSA-65 verify | 3.59 ms | 278 |
| Signed-log throughput | 11.49 ms/event | 87 |
| Chain verification | 4.16 ms/event | 241 |
| ML-KEM-768 keygen | 8.14 ms | 123 |
| ML-KEM-768 encapsulate | 6.72 ms | 149 |
| ML-KEM-768 decapsulate | 7.27 ms | 138 |
| Archive create | 8.57 ms | 117 |
| Archive decrypt | 7.68 ms | 130 |

> **Read these as an upper bound, not as libcrypto's speed.** This backend drives the `openssl`
> executable, so every figure includes process spawn plus temporary-file I/O — on the order of
> several milliseconds. The underlying ML-DSA-65 primitives in libcrypto are considerably faster
> than these end-to-end numbers suggest. The measurement is honest about what the framework
> actually costs today; it is not a measurement of ML-DSA itself.

### Pure-Python backend (dilithium-py 1.4.0 / kyber-py)

| Operation | Mean | Ops/s |
|---|---|---|
| ML-DSA-65 keygen | 7.77 ms | 129 |
| ML-DSA-65 sign | 55.72 ms | 18 |
| ML-DSA-65 verify | 9.24 ms | 108 |
| Signed-log throughput | 50.19 ms/event | 20 |
| Chain verification | 5.09 ms/event | 196 |
| ML-KEM-768 keygen | 3.18 ms | 315 |
| ML-KEM-768 encapsulate | 4.03 ms | 248 |
| ML-KEM-768 decapsulate | 5.39 ms | 186 |

### Sizes (identical for both backends — these are FIPS 204/203 constants)

| Item | Bytes |
|---|---|
| ML-DSA-65 signature | 3 309 |
| ML-DSA-65 public key | 1 952 |
| ML-DSA-65 private key | 4 032 (raw) |
| ML-KEM-768 encapsulation key | 1 184 |
| ML-KEM-768 decapsulation key | 2 400 |
| ML-KEM-768 ciphertext | 1 088 |

### Storage overhead

| | Bytes per event |
|---|---|
| Unsigned JSONL event | ~120 |
| Signed evidence record | ~4 900 |
| **Ratio** | **~40×** |

That ratio is the number to plan around. A node emitting 10 events/second produces roughly 100 MB
of unsigned log per day and about 4 GB signed. On a Raspberry Pi with an SD card, that matters more
than CPU time.

## Notes on the numbers

**ML-DSA signing has high variance.** It uses rejection sampling: the signer retries until it finds
an acceptable candidate, so the number of iterations — and therefore the time — differs per
signature. Observed standard deviation on the pure-Python backend is comparable to the mean. This is
inherent to the algorithm, not jitter in the harness. Report medians alongside means.

**Verification is much cheaper than signing**, and is deterministic. Verifying an archive of a
million events is dominated by I/O and JSON parsing, not by cryptography.

**ML-KEM is fast** relative to ML-DSA in both backends. Archive cost is dominated by compression and
disk, not by the KEM.

### Archive memory does not scale with archive size

Archives are processed in 1 MiB chunks in both directions, so peak memory is bounded by the chunk
size and the zlib window rather than by the file. Measured with `tracemalloc` over a 25 MB evidence
log on the development machine below:

| Operation | Peak additional memory |
|---|---|
| create-archive | ~7.4 MB |
| decrypt-archive | ~3.1 MB |

This is the property that matters on a Raspberry Pi: a node can seal a log substantially larger than
its free RAM. Reading is two-pass — the GCM tag is verified in full before any byte is decompressed
— which costs one extra pass over a temporary file and is deliberate: authenticating after
decompressing would mean handing attacker-chosen bytes to zlib.

Note that this bounds *archive* memory. It says nothing about signing throughput, which is bounded
by the ML-DSA times above plus two `fsync`s per event.

## Raspberry Pi guidance

Reproducing on a Pi:

```bash
ssh pi@192.168.50.21
```

```bash
cd ~/ics-deception && source .venv/bin/activate
```

```bash
ics-pqc-evidence benchmark --iterations 10 --chain-events 50 --output runtime/pi-bench.json --csv runtime/pi-bench.csv
```

Keep `--iterations` modest: a Pi 4 running the pure-Python backend takes roughly 10–20× longer per
signature than the desktop figures above, so a default run can take several minutes.

Then copy the results off — they contain no secrets:

```bash
scp pi@192.168.50.21:~/ics-deception/runtime/pi-bench.json ./
```

### Choosing a strategy on constrained hardware

| Strategy | When it fits |
|---|---|
| **Sign everything** (`sign`) | Low event volume, or a node with real CPU and storage headroom |
| **Sign selectively** | Preferred on a Pi: run with evidence `disabled` and sign only the events that matter (`sabotage_detected`, `login_attempt`) via a separate signing pass |
| **Batch offline** (`sign-log`) | Best throughput: log unsigned, then sign the rotated log with `ics-pqc-evidence sign-log`. One lock acquisition for the whole batch, and signing can run when the node is idle |
| **Sign on a collector** | Highest throughput and keeps no key on the honeypot — but then the signature attests to the *collector's* view, not the node's. A real trade-off, not a free win |

Install the native backend where you can: `sudo apt install openssl` on a distribution shipping
OpenSSL 3.5+ is the single biggest speed win available.

## Reproducing the reference results

```bash
make install-dev
```

```bash
ics-pqc-evidence capabilities
```

```bash
ics-pqc-evidence benchmark --backend openssl --iterations 15 --chain-events 100 --output runtime/openssl.json
```

```bash
ics-pqc-evidence benchmark --backend pyfips --iterations 15 --chain-events 100 --output runtime/pyfips.json
```

Every report embeds the environment and parameters it ran with, so two reports are directly
comparable — or provably not.

## Reporting checklist

- [ ] Hardware, OS and kernel
- [ ] Python and OpenSSL versions, and which backend was used
- [ ] `--iterations` and `--chain-events`
- [ ] Median as well as mean for signing (rejection sampling makes the mean misleading alone)
- [ ] Whether the machine was otherwise idle
- [ ] Storage overhead ratio, not only latency
- [ ] The JSON report attached (it contains no secrets)
