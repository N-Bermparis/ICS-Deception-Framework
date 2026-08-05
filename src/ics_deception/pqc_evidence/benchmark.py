"""Reproducible PQC benchmarks for Raspberry Pi and ordinary Linux systems.

Measures what actually matters when deciding whether a low-power deception node
can afford to sign every event:

* ML-DSA-65 key generation, signing and verification latency
* signatures per second, and signature / key sizes
* CPU time and peak RAM
* storage overhead of signed JSONL versus unsigned JSONL
* chain verification throughput
* ML-KEM-768 encapsulation and decapsulation
* archive creation and decryption time, and AES-GCM overhead

Every run records the hardware, OS, Python, OpenSSL and backend details, plus
the parameters used, so a number can be reproduced or fairly compared.

Nothing sensitive is emitted: keys are generated in memory, never written, and
never appear in the output.
"""

from __future__ import annotations

import csv
import gc
import json
import os
import platform
import resource
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import DEFAULT_SIGNATURE_ALGORITHM, EvidenceError
from ics_deception.pqc_evidence.crypto_backend import CryptoBackend, select_backend

__all__ = ["BenchmarkError", "BenchmarkSuite", "run_benchmarks"]

DEFAULT_ITERATIONS = 20
DEFAULT_CHAIN_EVENTS = 200


class BenchmarkError(EvidenceError):
    """A benchmark could not run."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _peak_rss_kib() -> int:
    """Peak resident set size in KiB.

    ``ru_maxrss`` is KiB on Linux but bytes on macOS; normalise to KiB.
    """
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return usage // 1024 if sys.platform == "darwin" else usage


@dataclass
class Measurement:
    """Timing statistics for one operation, in milliseconds."""

    name: str
    iterations: int
    mean_ms: float
    median_ms: float
    min_ms: float
    max_ms: float
    stdev_ms: float
    ops_per_second: float
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable measurement."""
        return {
            "name": self.name,
            "iterations": self.iterations,
            "mean_ms": round(self.mean_ms, 4),
            "median_ms": round(self.median_ms, 4),
            "min_ms": round(self.min_ms, 4),
            "max_ms": round(self.max_ms, 4),
            "stdev_ms": round(self.stdev_ms, 4),
            "ops_per_second": round(self.ops_per_second, 2),
            **self.extra,
        }


def _time_it(name: str, iterations: int, operation: Callable[[], Any], **extra: Any) -> Measurement:
    """Run ``operation`` ``iterations`` times and summarise the timings."""
    if iterations < 1:
        raise BenchmarkError("iterations must be greater than zero")
    samples: list[float] = []
    gc.collect()
    # One untimed warm-up run: the first call pays for lazy imports and table
    # construction, which would otherwise dominate a short benchmark.
    operation()
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - start) * 1000.0)
    mean = statistics.fmean(samples)
    return Measurement(
        name=name,
        iterations=iterations,
        mean_ms=mean,
        median_ms=statistics.median(samples),
        min_ms=min(samples),
        max_ms=max(samples),
        stdev_ms=statistics.stdev(samples) if len(samples) > 1 else 0.0,
        ops_per_second=(1000.0 / mean) if mean > 0 else float("inf"),
        extra=extra,
    )


def environment_report(backend: CryptoBackend) -> dict[str, Any]:
    """Describe the machine and toolchain the benchmark ran on."""
    capabilities = backend.capabilities()
    openssl_version = ""
    try:
        import ssl

        openssl_version = ssl.OPENSSL_VERSION
    except Exception:  # pragma: no cover
        openssl_version = "unknown"

    cpu_model = ""
    try:
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.is_file():
            for line in cpuinfo.read_text(errors="replace").splitlines():
                if line.lower().startswith(("model name", "hardware")):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except OSError:  # pragma: no cover
        pass

    return {
        "timestamp": _utc_now(),
        "hostname_hash": "",  # deliberately empty: no host identity in results
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or cpu_model,
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_ssl_openssl": openssl_version,
        "backend": capabilities.name,
        "backend_provider": capabilities.provider,
        "backend_version": capabilities.version,
        "backend_real_pqc": capabilities.real_pqc,
    }


class BenchmarkSuite:
    """Runs the benchmark set and collects results."""

    def __init__(
        self,
        backend: CryptoBackend | None = None,
        algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
        iterations: int = DEFAULT_ITERATIONS,
        chain_events: int = DEFAULT_CHAIN_EVENTS,
        include_archive: bool = True,
    ) -> None:
        if iterations < 1:
            raise BenchmarkError("iterations must be greater than zero")
        if chain_events < 1:
            raise BenchmarkError("chain_events must be greater than zero")
        self.algorithm = algorithm
        self.iterations = iterations
        self.chain_events = chain_events
        self.include_archive = include_archive
        self.backend = backend if backend is not None else select_backend(algorithm=algorithm)
        self.measurements: list[Measurement] = []

    def run(self) -> dict[str, Any]:
        """Run every benchmark and return the full report."""
        started = time.perf_counter()
        self.measurements = []

        keypair = self._bench_signatures()
        self._bench_chain(keypair)
        if self.include_archive:
            self._bench_kem_and_archive()

        duration = time.perf_counter() - started
        return {
            "schema": "ics-deception/pqc-benchmark/1.0",
            "environment": environment_report(self.backend),
            "parameters": {
                "algorithm": self.algorithm,
                "iterations": self.iterations,
                "chain_events": self.chain_events,
                "include_archive": self.include_archive,
            },
            "measurements": [m.to_dict() for m in self.measurements],
            "totals": {
                "duration_seconds": round(duration, 3),
                "peak_rss_kib": _peak_rss_kib(),
                "cpu_time_seconds": round(time.process_time(), 3),
            },
        }

    # -- individual benchmarks --------------------------------------------

    def _bench_signatures(self):
        from ics_deception.pqc_evidence.crypto_backend import KeyPair

        holder: dict[str, KeyPair] = {}

        def keygen() -> None:
            holder["kp"] = self.backend.generate_keypair(self.algorithm)

        self.measurements.append(_time_it("mldsa_keygen", self.iterations, keygen))
        keypair = holder["kp"]

        payload = json.dumps(
            {
                "source": "modbus_honeypot",
                "event_type": "critical_register_write",
                "client_ip": "192.168.1.50",
                "register": 40001,
                "value": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        signature_holder: dict[str, bytes] = {}

        def sign() -> None:
            signature_holder["sig"] = self.backend.sign(
                keypair.private_bytes, payload, self.algorithm
            )

        self.measurements.append(
            _time_it(
                "mldsa_sign",
                self.iterations,
                sign,
                payload_bytes=len(payload),
            )
        )
        signature = signature_holder["sig"]

        def verify() -> None:
            self.backend.verify(keypair.public_bytes, payload, signature, self.algorithm)

        self.measurements.append(_time_it("mldsa_verify", self.iterations, verify))

        self.measurements.append(
            Measurement(
                name="sizes",
                iterations=1,
                mean_ms=0.0,
                median_ms=0.0,
                min_ms=0.0,
                max_ms=0.0,
                stdev_ms=0.0,
                ops_per_second=0.0,
                extra={
                    "signature_bytes": len(signature),
                    "public_key_bytes": len(keypair.public_bytes),
                    "private_key_bytes": len(keypair.private_bytes),
                },
            )
        )
        return keypair

    def _bench_chain(self, keypair) -> None:
        """Measure signed-log throughput, storage overhead and verification."""
        import tempfile

        from ics_deception.pqc_evidence.collector import EvidenceCollector
        from ics_deception.pqc_evidence.key_registry import KeyRegistry
        from ics_deception.pqc_evidence.signer import EvidenceSigner

        node_id = "benchmark-node"
        key_id = "benchmark-node-key"
        events = [
            {
                "source": "modbus_honeypot",
                "event_type": "modbus_request",
                "client_ip": "192.168.1.50",
                "function_code": 3,
                "sequence_number": index,
            }
            for index in range(self.chain_events)
        ]
        unsigned_bytes = sum(
            len(json.dumps(e, separators=(",", ":"), sort_keys=True)) + 1 for e in events
        )

        with tempfile.TemporaryDirectory(prefix="ics-pqc-bench-") as workdir:
            state_path = Path(workdir) / "state.json"
            evidence_path = Path(workdir) / "evidence.jsonl"
            signer = EvidenceSigner(
                node_id,
                key_id,
                keypair.private_bytes,
                state_path,
                evidence_path=evidence_path,
                backend=self.backend,
            )
            start = time.perf_counter()
            report = signer.sign_log(json.dumps(e) for e in events)
            sign_seconds = time.perf_counter() - start
            signed_text = evidence_path.read_text(encoding="utf-8")

            registry = KeyRegistry()
            registry.register(key_id, node_id, keypair.public_bytes)
            collector = EvidenceCollector(registry, allow_test_backend=True)

            start = time.perf_counter()
            stream_report = collector.verify_stream(signed_text.splitlines())
            verify_seconds = time.perf_counter() - start

        signed_bytes = len(signed_text.encode("utf-8"))
        self.measurements.append(
            Measurement(
                name="signed_log_throughput",
                iterations=self.chain_events,
                mean_ms=(sign_seconds * 1000.0) / max(self.chain_events, 1),
                median_ms=0.0,
                min_ms=0.0,
                max_ms=0.0,
                stdev_ms=0.0,
                ops_per_second=(self.chain_events / sign_seconds) if sign_seconds else 0.0,
                extra={
                    "events": report.signed,
                    "unsigned_bytes": unsigned_bytes,
                    "signed_bytes": signed_bytes,
                    "storage_overhead_ratio": round(signed_bytes / max(unsigned_bytes, 1), 2),
                    "bytes_per_event": signed_bytes // max(self.chain_events, 1),
                },
            )
        )
        self.measurements.append(
            Measurement(
                name="chain_verification_throughput",
                iterations=self.chain_events,
                mean_ms=(verify_seconds * 1000.0) / max(self.chain_events, 1),
                median_ms=0.0,
                min_ms=0.0,
                max_ms=0.0,
                stdev_ms=0.0,
                ops_per_second=(self.chain_events / verify_seconds) if verify_seconds else 0.0,
                extra={"verified": stream_report.verified, "failed": stream_report.failed},
            )
        )

    def _bench_kem_and_archive(self) -> None:
        """Measure ML-KEM-768 and archive create/decrypt cost."""
        import tempfile

        from ics_deception.pqc_evidence.archive import create_archive, decrypt_archive

        capabilities = self.backend.capabilities()
        if "ML-KEM-768" not in capabilities.kem_algorithms:
            self.measurements.append(
                Measurement(
                    name="mlkem_skipped",
                    iterations=0,
                    mean_ms=0.0,
                    median_ms=0.0,
                    min_ms=0.0,
                    max_ms=0.0,
                    stdev_ms=0.0,
                    ops_per_second=0.0,
                    extra={"reason": f"{self.backend.name} does not provide ML-KEM-768"},
                )
            )
            return

        holder: dict[str, Any] = {}

        def kem_keygen() -> None:
            holder["kp"] = self.backend.kem_generate_keypair("ML-KEM-768")

        self.measurements.append(_time_it("mlkem_keygen", self.iterations, kem_keygen))
        kem_keypair = holder["kp"]

        def encaps() -> None:
            holder["result"] = self.backend.kem_encapsulate(
                kem_keypair.public_bytes, "ML-KEM-768"
            )

        self.measurements.append(_time_it("mlkem_encapsulate", self.iterations, encaps))
        _, ciphertext = holder["result"]

        def decaps() -> None:
            self.backend.kem_decapsulate(kem_keypair.private_bytes, ciphertext, "ML-KEM-768")

        self.measurements.append(
            _time_it(
                "mlkem_decapsulate",
                self.iterations,
                decaps,
                ciphertext_bytes=len(ciphertext),
                encapsulation_key_bytes=len(kem_keypair.public_bytes),
            )
        )

        with tempfile.TemporaryDirectory(prefix="ics-pqc-bench-") as workdir:
            evidence = Path(workdir) / "evidence.jsonl"
            payload = "\n".join(
                json.dumps({"sequence": i, "event_hash": f"{i:064x}"}) for i in range(500)
            )
            evidence.write_text(payload, encoding="utf-8")
            archive_path = Path(workdir) / "evidence.pqcarch"

            def create() -> None:
                create_archive(
                    evidence,
                    archive_path,
                    kem_keypair.public_bytes,
                    node_id="benchmark-node",
                    backend=self.backend,
                    overwrite=True,
                )


            self.measurements.append(
                _time_it(
                    "archive_create",
                    max(1, self.iterations // 4),
                    create,
                    plaintext_bytes=len(payload),
                )
            )
            archive_bytes = archive_path.stat().st_size

            def decrypt() -> None:
                decrypt_archive(
                    archive_path, kem_keypair.private_bytes, backend=self.backend
                )

            self.measurements.append(
                _time_it(
                    "archive_decrypt",
                    max(1, self.iterations // 4),
                    decrypt,
                    archive_bytes=archive_bytes,
                    aead_overhead_bytes=archive_bytes - len(payload),
                )
            )


def run_benchmarks(
    backend_name: str | None = None,
    algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
    iterations: int = DEFAULT_ITERATIONS,
    chain_events: int = DEFAULT_CHAIN_EVENTS,
    include_archive: bool = True,
    allow_test_backend: bool = False,
) -> dict[str, Any]:
    """Run the suite and return the report."""
    backend = select_backend(
        name=backend_name, algorithm=algorithm, allow_test_backend=allow_test_backend
    )
    suite = BenchmarkSuite(
        backend=backend,
        algorithm=algorithm,
        iterations=iterations,
        chain_events=chain_events,
        include_archive=include_archive,
    )
    return suite.run()


def write_csv(report: dict[str, Any], path: str | Path) -> Path:
    """Write the measurements as CSV alongside the JSON report."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    measurements = report.get("measurements", [])
    columns: list[str] = []
    for measurement in measurements:
        for key in measurement:
            if key not in columns:
                columns.append(key)
    with open(destination, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for measurement in measurements:
            writer.writerow(measurement)
    return destination
