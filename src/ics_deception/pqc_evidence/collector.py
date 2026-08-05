"""Evidence collector: verify a single record, a stream, or a whole archive.

The per-record verifier answers "is this record sound?". The collector answers
the questions that only make sense across a *sequence* of records:

* were events **deleted**? (sequence gaps)
* were they **reordered**? (previous-hash mismatch with a rewound sequence)
* were they **duplicated** or **replayed**? (sequence or event-hash seen before)
* are there **competing** events claiming the same sequence? (same sequence,
  different hash — a fork)
* did a node **restart** its chain? (a fresh genesis mid-stream)

Each node is tracked independently, so a file interleaving several nodes is
verified correctly.

Memory is bounded: only per-node cursors and seen-hash sets are retained, never
the events themselves, so a multi-gigabyte log verifies in constant memory with
respect to event *content*.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import EvidenceError
from ics_deception.pqc_evidence.event_chain import ChainPosition, compute_event_hash
from ics_deception.pqc_evidence.key_registry import KeyRegistry
from ics_deception.pqc_evidence.models import MAX_EVIDENCE_BYTES, SignedEvent
from ics_deception.pqc_evidence.verifier import (
    EvidenceVerifier,
    VerificationResult,
)

__all__ = ["CollectorError", "EvidenceCollector", "StreamReport"]

#: Cap on distinct event hashes remembered per node for replay detection.
#: 1e6 hashes is roughly 100 MB of Python strings — generous for a research
#: deployment, and bounded so a hostile log cannot exhaust memory.
MAX_TRACKED_HASHES = 1_000_000


class CollectorError(EvidenceError):
    """The collector could not process the input."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


@dataclass
class StreamReport:
    """Aggregate outcome of verifying a stream of evidence."""

    valid: bool = True
    total: int = 0
    verified: int = 0
    failed: int = 0
    malformed: int = 0
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: Alert code -> number of records raising it.
    alert_counts: dict[str, int] = field(default_factory=dict)
    #: Per-record results, capped so a huge log cannot exhaust memory.
    results: list[dict[str, Any]] = field(default_factory=list)
    truncated_results: bool = False
    started_at: str = field(default_factory=_utc_now)
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the structured report."""
        return {
            "valid": self.valid,
            "total": self.total,
            "verified": self.verified,
            "failed": self.failed,
            "malformed": self.malformed,
            "nodes": self.nodes,
            "alert_counts": dict(sorted(self.alert_counts.items())),
            "results": self.results,
            "truncated_results": self.truncated_results,
            "started_at": self.started_at,
            "finished_at": self.finished_at or _utc_now(),
        }


class _NodeTracker:
    """Per-node chain cursor plus duplicate/replay detection sets."""

    def __init__(self, node_id: str) -> None:
        self.position = ChainPosition(node_id=node_id)
        self.seen_sequences: dict[int, str] = {}
        self.seen_hashes: set[str] = set()
        self.tracking_exhausted = False

    def note(self, event: SignedEvent) -> list[tuple[str, str]]:
        """Record an event and return any (alert, detail) pairs it triggers."""
        alerts: list[tuple[str, str]] = []

        previous_hash = self.seen_sequences.get(event.sequence)
        if previous_hash is not None:
            if previous_hash == event.event_hash:
                alerts.append(
                    (
                        "pqc_replayed_event",
                        f"event {event.node_id}#{event.sequence} with hash "
                        f"{event.event_hash[:16]}... appears more than once",
                    )
                )
            else:
                alerts.append(
                    (
                        "pqc_duplicate_sequence",
                        f"two different events claim sequence {event.sequence} for node "
                        f"{event.node_id!r} (hashes {previous_hash[:16]}... and "
                        f"{event.event_hash[:16]}...); the chain has forked",
                    )
                )
        elif event.event_hash in self.seen_hashes:
            alerts.append(
                (
                    "pqc_replayed_event",
                    f"event hash {event.event_hash[:16]}... reappears at a different "
                    f"sequence ({event.sequence}) for node {event.node_id!r}",
                )
            )

        if len(self.seen_hashes) < MAX_TRACKED_HASHES:
            self.seen_sequences[event.sequence] = event.event_hash
            self.seen_hashes.add(event.event_hash)
        elif not self.tracking_exhausted:
            self.tracking_exhausted = True
            alerts.append(
                (
                    "pqc_malformed_evidence",
                    f"more than {MAX_TRACKED_HASHES} events for node {event.node_id!r}; "
                    "replay detection is no longer exhaustive for this stream",
                )
            )
        return alerts

    def summary(self) -> dict[str, Any]:
        """Return this node's chain summary."""
        return {
            "last_sequence": self.position.last_sequence,
            "last_event_hash": self.position.last_event_hash,
            "events": len(self.seen_sequences),
        }


class EvidenceCollector:
    """Verifies evidence records, streams and archives against a registry."""

    def __init__(
        self,
        registry: KeyRegistry,
        verifier: EvidenceVerifier | None = None,
        max_results: int = 10_000,
        max_record_bytes: int = MAX_EVIDENCE_BYTES,
        allow_test_backend: bool = False,
    ) -> None:
        if max_record_bytes <= 0:
            raise CollectorError("max_record_bytes must be greater than zero")
        if max_results <= 0:
            raise CollectorError("max_results must be greater than zero")
        self.registry = registry
        # The limit is pushed into the verifier, which is what actually parses.
        # Holding it only here — as an earlier version did — meant configuring
        # it changed nothing at all.
        self.verifier = verifier or EvidenceVerifier(
            registry,
            allow_test_backend=allow_test_backend,
            max_record_bytes=max_record_bytes,
        )
        if verifier is not None:
            self.verifier.max_record_bytes = max_record_bytes
        self.max_results = max_results
        self.max_record_bytes = max_record_bytes

    # -- one record --------------------------------------------------------

    def verify_one(self, line: str | bytes) -> VerificationResult:
        """Verify a single JSONL record with no chain context."""
        result, _ = self.verifier.verify_line(line)
        return result

    # -- streams -----------------------------------------------------------

    def verify_stream(self, lines: Iterable[str | bytes]) -> StreamReport:
        """Verify an iterable of JSONL records, tracking every node's chain."""
        report = StreamReport()
        trackers: dict[str, _NodeTracker] = {}

        for raw in lines:
            text = raw.strip() if isinstance(raw, str) else raw.strip()
            if not text:
                continue
            report.total += 1

            # Reject an oversized line on its raw length, before it is handed to
            # any parser, so a hostile 100 MB line costs one length check.
            if len(text) > self.max_record_bytes:
                oversized = VerificationResult(valid=False)
                oversized.add_error(
                    "pqc_oversized_evidence",
                    f"record is {len(text)} bytes, exceeding the "
                    f"{self.max_record_bytes} byte limit",
                )
                report.malformed += 1
                report.failed += 1
                report.valid = False
                self._record(report, oversized)
                continue

            result, event = self.verifier.verify_line(text)

            if event is None:
                report.malformed += 1
                report.failed += 1
                report.valid = False
                self._record(report, result)
                continue

            tracker = trackers.get(event.node_id)
            if tracker is None:
                tracker = _NodeTracker(event.node_id)
                trackers[event.node_id] = tracker

            # Chain linkage is checked against this node's cursor.
            self.verifier._check_chain(event, tracker.position, result)  # noqa: SLF001
            for alert, detail in tracker.note(event):
                result.add_error(alert, detail)

            # Advance whenever the record sits at the expected position, but
            # link the chain to the *recomputed* hash rather than the claimed
            # one. A tampered record therefore reports its own hash mismatch and
            # breaks the link to the next record, instead of also producing a
            # cascade of misleading "sequence gap" alerts for every record after
            # it, and a forger cannot steer the chain by claiming a hash.
            if event.sequence == tracker.position.next_sequence:
                tracker.position.advance(event, event_hash=compute_event_hash(event))

            if result.valid:
                report.verified += 1
            else:
                report.failed += 1
                report.valid = False
            self._record(report, result)

        report.nodes = {node: tracker.summary() for node, tracker in trackers.items()}
        report.finished_at = _utc_now()
        return report

    def verify_file(self, path: str | Path) -> StreamReport:
        """Verify a JSONL evidence file.

        An empty file is valid and reports zero records. A final line without a
        trailing newline is handled like any other line.
        """
        evidence_path = Path(path).expanduser()
        if not evidence_path.is_file():
            raise CollectorError(f"evidence file not found: {evidence_path}")
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as handle:
                return self.verify_stream(handle)
        except OSError as exc:
            raise CollectorError(f"cannot read {evidence_path}: {exc}") from exc

    def iter_valid_events(self, lines: Iterable[str]) -> Iterator[SignedEvent]:
        """Yield only records that verify, for downstream consumers."""
        for raw in lines:
            text = raw.strip()
            if not text:
                continue
            result, event = self.verifier.verify_line(text)
            if result.valid and event is not None:
                yield event

    def _record(self, report: StreamReport, result: VerificationResult) -> None:
        for alert in result.errors:
            report.alert_counts[alert] = report.alert_counts.get(alert, 0) + 1
        for alert in result.warnings:
            report.alert_counts[alert] = report.alert_counts.get(alert, 0) + 1
        if len(report.results) < self.max_results:
            report.results.append(result.to_dict())
        else:
            report.truncated_results = True
