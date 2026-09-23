"""``ics-pqc-evidence`` — command line for the post-quantum evidence seal.

Every subcommand:

* validates its input strictly,
* exits non-zero on failure (see :data:`EXIT_CODES`),
* supports ``--json`` for machine-readable output and human text otherwise,
* refuses to overwrite files unless ``--force`` is given,
* never prints private key material,
* distinguishes *warnings* from *verification failures*.

Exit codes
----------
``0`` success; ``1`` verification failed; ``2`` usage or input error;
``3`` no cryptographic backend available; ``4`` I/O or state error.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ics_deception.common.argtypes import positive_int
from ics_deception.pqc_evidence import (
    DEFAULT_SIGNATURE_ALGORITHM,
    EVIDENCE_FORMAT_VERSION,
    EvidenceError,
)
from ics_deception.pqc_evidence.archive import (
    ArchiveError,
    create_archive,
    decrypt_archive,
    verify_archive,
)
from ics_deception.pqc_evidence.collector import EvidenceCollector
from ics_deception.pqc_evidence.crypto_backend import (
    TEST_BACKEND,
    BackendError,
    BackendUnavailableError,
    describe_capabilities,
    select_backend,
)
from ics_deception.pqc_evidence.key_registry import (
    KeyRegistry,
    KeyRegistryError,
    load_public_key_file,
)
from ics_deception.pqc_evidence.signer import (
    EvidenceSigner,
    SignerError,
    load_private_key,
    write_private_key,
)

__all__ = ["EXIT_CODES", "main"]

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USAGE = 2
EXIT_NO_BACKEND = 3
EXIT_IO = 4

EXIT_CODES = {
    "ok": EXIT_OK,
    "verification_failed": EXIT_VERIFICATION_FAILED,
    "usage": EXIT_USAGE,
    "no_backend": EXIT_NO_BACKEND,
    "io": EXIT_IO,
}

DEFAULT_REGISTRY = "runtime/pqc/registry.json"
DEFAULT_STATE = "runtime/pqc/state.json"


def _emit(payload: dict[str, Any], as_json: bool, human: str = "") -> None:
    """Print either machine-readable JSON or a human summary."""
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif human:
        print(human)


def _fail(message: str, as_json: bool, code: str = "error") -> None:
    if as_json:
        print(json.dumps({"ok": False, "error": code, "detail": message}, indent=2))
    else:
        print(f"error: {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# capabilities
# ---------------------------------------------------------------------------


def cmd_capabilities(args: argparse.Namespace) -> int:
    """Report which cryptographic backends are usable."""
    report = describe_capabilities()
    report["evidence_format_version"] = EVIDENCE_FORMAT_VERSION
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return EXIT_OK if report["real_pqc_available"] else EXIT_NO_BACKEND

    print(f"evidence format version : {EVIDENCE_FORMAT_VERSION}")
    print(f"default algorithm       : {report['default_signature_algorithm']}")
    print(f"production mode         : {report['production_mode']}")
    print(f"preferred backend       : {report['preferred_backend'] or 'NONE'}")
    print("")
    for backend in report["backends"]:
        status = "available" if backend["available"] else "unavailable"
        kind = "real PQC" if backend["real_pqc"] else "TEST ONLY - NO SECURITY"
        print(f"  {backend['name']:20s} {status:12s} [{kind}]")
        if backend["version"]:
            print(f"      version   : {backend['version']}")
        if backend["provider"]:
            print(f"      provider  : {backend['provider']}")
        if backend["signature_algorithms"]:
            print(f"      signatures: {', '.join(backend['signature_algorithms'])}")
        if backend["kem_algorithms"]:
            print(f"      KEMs      : {', '.join(backend['kem_algorithms'])}")
        if backend["reason"]:
            print(f"      reason    : {backend['reason']}")
    if not report["real_pqc_available"]:
        print("\nNo real post-quantum backend is available.", file=sys.stderr)
        print(
            "Install one with: pip install 'ics-deception[pqc]'  "
            "(or install OpenSSL 3.5+ for the native backend)",
            file=sys.stderr,
        )
        return EXIT_NO_BACKEND
    return EXIT_OK


# ---------------------------------------------------------------------------
# key management
# ---------------------------------------------------------------------------


def _key_protection_note() -> str:
    """Describe the on-disk protection actually applied to a new private key.

    POSIX gets a real 0600. Windows has no such mode bit, so reporting
    "mode 0600" there would promise a protection the filesystem never applied.
    """
    if os.name == "nt":
        return "restrict access via ACLs - NEVER commit or copy this"
    return "mode 0600 - NEVER commit or copy this"


def cmd_generate_key(args: argparse.Namespace) -> int:
    """Generate a node signing key pair."""
    try:
        backend = select_backend(
            name=args.backend,
            algorithm=args.algorithm,
            allow_test_backend=args.allow_test_backend,
        )
    except BackendUnavailableError as exc:
        _fail(exc.detail, args.json, "no_backend")
        return EXIT_NO_BACKEND

    private_path = Path(args.private_key)
    public_path = Path(args.public_key) if args.public_key else private_path.with_suffix(".pub")

    if private_path.exists() and not args.force:
        _fail(
            f"{private_path} already exists; refusing to overwrite a signing key "
            "(use --force only if you are certain)",
            args.json,
            "exists",
        )
        return EXIT_USAGE

    try:
        keypair = backend.generate_keypair(args.algorithm)
    except BackendError as exc:
        _fail(exc.detail, args.json, exc.code)
        return EXIT_NO_BACKEND

    try:
        if private_path.exists() and args.force:
            private_path.unlink()
        write_private_key(private_path, keypair)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.write_text(
            base64.b64encode(keypair.public_bytes).decode("ascii") + "\n", encoding="utf-8"
        )
        os.chmod(public_path, 0o644)
    except (SignerError, OSError) as exc:
        _fail(str(exc), args.json, "io")
        return EXIT_IO

    from ics_deception.pqc_evidence.key_registry import fingerprint

    payload = {
        "ok": True,
        "algorithm": args.algorithm,
        "backend": backend.name,
        "real_pqc": backend.capabilities().real_pqc,
        "private_key": str(private_path),
        "public_key": str(public_path),
        "public_key_bytes": len(keypair.public_bytes),
        "fingerprint": fingerprint(keypair.public_bytes),
    }
    _emit(
        payload,
        args.json,
        f"generated {args.algorithm} key pair using the {backend.name} backend\n"
        f"  private key : {private_path} ({_key_protection_note()})\n"
        f"  public key  : {public_path}\n"
        f"  fingerprint : {payload['fingerprint']}",
    )
    if not backend.capabilities().real_pqc:
        print(
            "WARNING: this key came from the insecure test backend and provides NO security.",
            file=sys.stderr,
        )
    return EXIT_OK


def cmd_register_key(args: argparse.Namespace) -> int:
    """Add a node's public key to the trusted registry."""
    try:
        registry = KeyRegistry.load(args.registry)
        public_key = load_public_key_file(args.public_key)
        registry.register(
            key_id=args.key_id,
            node_id=args.node_id,
            public_key=public_key,
            algorithm=args.algorithm,
            activated_at=args.activated_at,
            expires_at=args.expires_at,
            make_active=not args.inactive,
        )
        registry.save(args.registry)
    except (KeyRegistryError, EvidenceError) as exc:
        _fail(str(exc), args.json, "registry")
        return EXIT_USAGE

    record = registry.get(args.key_id)
    payload = {
        "ok": True,
        "key_id": args.key_id,
        "node_id": args.node_id,
        "state": record.state.value if record else "unknown",
        "fingerprint": record.fingerprint if record else "",
        "registry": str(args.registry),
        "keys_in_registry": len(registry),
    }
    _emit(
        payload,
        args.json,
        f"registered key {args.key_id} for node {args.node_id}\n"
        f"  fingerprint : {payload['fingerprint']}\n"
        f"  registry    : {args.registry} ({len(registry)} key(s))",
    )
    return EXIT_OK


def cmd_rotate_key(args: argparse.Namespace) -> int:
    """Register a new active key, marking the previous one rotated."""
    try:
        registry = KeyRegistry.load(args.registry)
        public_key = load_public_key_file(args.public_key)
        registry.rotate(args.node_id, args.key_id, public_key, algorithm=args.algorithm)
        registry.save(args.registry)
    except (KeyRegistryError, EvidenceError) as exc:
        _fail(str(exc), args.json, "registry")
        return EXIT_USAGE

    rotated = [r.key_id for r in registry.for_node(args.node_id) if r.state.value == "rotated"]
    payload = {
        "ok": True,
        "node_id": args.node_id,
        "new_active_key": args.key_id,
        "rotated_keys": rotated,
        "registry": str(args.registry),
    }
    _emit(
        payload,
        args.json,
        f"rotated node {args.node_id} to key {args.key_id}\n"
        f"  previously active: {', '.join(rotated) or 'none'}\n"
        "  historical events signed by rotated keys still verify",
    )
    return EXIT_OK


def cmd_revoke_key(args: argparse.Namespace) -> int:
    """Revoke a key so its events stop being trusted."""
    try:
        registry = KeyRegistry.load(args.registry)
        registry.revoke(args.key_id, args.reason)
        registry.save(args.registry)
    except KeyRegistryError as exc:
        _fail(str(exc), args.json, "registry")
        return EXIT_USAGE

    payload = {"ok": True, "key_id": args.key_id, "reason": args.reason, "state": "revoked"}
    _emit(
        payload,
        args.json,
        f"revoked key {args.key_id}: {args.reason}\n"
        "  events signed by this key will now report pqc_revoked_key",
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# signing
# ---------------------------------------------------------------------------


def _build_signer(args: argparse.Namespace) -> EvidenceSigner:
    private_key = load_private_key(args.private_key, require_strict_permissions=not args.force)
    algorithm = getattr(args, "algorithm", None) or DEFAULT_SIGNATURE_ALGORITHM
    backend = select_backend(
        name=getattr(args, "backend", None),
        algorithm=algorithm,
        allow_test_backend=getattr(args, "allow_test_backend", False),
        for_private_key=private_key,
    )
    # ``sign-log`` names the evidence log ``--output``; the read-only and
    # administrative commands name it ``--evidence``. Either must reach the
    # signer, or a node whose log is not at the default path is inspected — or
    # worse, repaired — against the wrong file.
    evidence = getattr(args, "evidence", None) or getattr(args, "output", None) or None
    return EvidenceSigner(
        node_id=args.node_id,
        key_id=args.key_id,
        private_key=private_key,
        state_path=args.state,
        evidence_path=evidence,
        backend=backend,
        algorithm=algorithm,
    )


def cmd_sign_event(args: argparse.Namespace) -> int:
    """Sign a single JSON event read from a file or stdin."""
    try:
        raw = sys.stdin.read() if args.event in ("-", None) else Path(args.event).read_text(
            encoding="utf-8"
        )
    except OSError as exc:
        _fail(f"cannot read event: {exc}", args.json, "io")
        return EXIT_IO

    try:
        event = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        _fail(f"event is not valid JSON: {exc}", args.json, "usage")
        return EXIT_USAGE
    if not isinstance(event, dict):
        _fail("event must be a JSON object", args.json, "usage")
        return EXIT_USAGE

    try:
        signer = _build_signer(args)
        record = signer.sign_event(event)
    except BackendUnavailableError as exc:
        _fail(exc.detail, args.json, "no_backend")
        return EXIT_NO_BACKEND
    except (EvidenceError, OSError) as exc:
        _fail(str(exc), args.json, "sign")
        return EXIT_IO

    # The record is already durably appended to the evidence log by the signer;
    # writing it again here would duplicate a sequence number.
    _emit(
        {
            "ok": True,
            "sequence": record.sequence,
            "event_hash": record.event_hash,
            "evidence_log": str(signer.evidence_path),
        },
        args.json,
        f"signed sequence {record.sequence} -> {signer.evidence_path}",
    )
    if args.print_record:
        print(record.to_json_line())
    return EXIT_OK


def cmd_sign_log(args: argparse.Namespace) -> int:
    """Sign every JSON line of an unsigned log into a signed evidence log."""
    try:
        signer = _build_signer(args)
    except BackendUnavailableError as exc:
        _fail(exc.detail, args.json, "no_backend")
        return EXIT_NO_BACKEND
    except (EvidenceError, OSError) as exc:
        _fail(str(exc), args.json, "sign")
        return EXIT_IO

    output_path = Path(args.output)

    try:
        # Not a context manager: stdin must not be closed, and the handle is
        # closed in the finally block below either way.
        source_handle = (
            sys.stdin
            if args.input in ("-", None)
            else open(args.input, encoding="utf-8")  # noqa: SIM115
        )
    except OSError as exc:
        _fail(f"cannot read {args.input}: {exc}", args.json, "io")
        return EXIT_IO

    try:
        # The signer owns the evidence log and appends transactionally, so the
        # output file is never opened here. Appending to an existing chain is
        # the normal case, not something that needs --force.
        report = signer.sign_log(source_handle, max_events=args.max_events)
    except (EvidenceError, OSError) as exc:
        _fail(str(exc), args.json, "sign")
        return EXIT_IO
    finally:
        if source_handle is not sys.stdin:
            source_handle.close()

    payload = {"ok": True, **report.to_dict(), "output": str(output_path)}
    _emit(
        payload,
        args.json,
        f"signed {report.signed} event(s) into {output_path}\n"
        f"  sequences {report.first_sequence}..{report.last_sequence}\n"
        f"  skipped {report.skipped}, errors {report.errors}, backend {report.backend}",
    )
    return EXIT_OK if report.errors == 0 else EXIT_VERIFICATION_FAILED


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------


def _collector(args: argparse.Namespace) -> EvidenceCollector:
    registry = KeyRegistry.load(args.registry)
    return EvidenceCollector(
        registry, allow_test_backend=getattr(args, "allow_test_backend", False)
    )


def cmd_verify_event(args: argparse.Namespace) -> int:
    """Verify one signed evidence record."""
    try:
        raw = sys.stdin.read() if args.event in ("-", None) else Path(args.event).read_text(
            encoding="utf-8"
        )
    except OSError as exc:
        _fail(f"cannot read evidence: {exc}", args.json, "io")
        return EXIT_IO

    try:
        collector = _collector(args)
        result = collector.verify_one(raw.strip())
    except (KeyRegistryError, EvidenceError) as exc:
        _fail(str(exc), args.json, "verify")
        return EXIT_USAGE

    payload = result.to_dict()
    _emit(
        payload,
        args.json,
        _format_result(payload),
    )
    return EXIT_OK if result.valid else EXIT_VERIFICATION_FAILED


def cmd_verify_log(args: argparse.Namespace) -> int:
    """Verify a whole signed evidence log, including chain continuity."""
    try:
        collector = _collector(args)
        if args.input in ("-", None):
            report = collector.verify_stream(sys.stdin)
        else:
            report = collector.verify_file(args.input)
    except (KeyRegistryError, EvidenceError) as exc:
        _fail(str(exc), args.json, "verify")
        return EXIT_USAGE

    payload = report.to_dict()
    if not args.include_results:
        payload.pop("results", None)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        status = "VALID" if report.valid else "FAILED"
        print(f"evidence log verification: {status}")
        print(f"  records   : {report.total}")
        print(f"  verified  : {report.verified}")
        print(f"  failed    : {report.failed}")
        print(f"  malformed : {report.malformed}")
        for node, summary in sorted(report.nodes.items()):
            print(
                f"  node {node}: {summary['events']} event(s), "
                f"last sequence {summary['last_sequence']}"
            )
        if report.alert_counts:
            print("  alerts:")
            for alert, count in sorted(report.alert_counts.items()):
                print(f"    {alert:32s} {count}")
    return EXIT_OK if report.valid else EXIT_VERIFICATION_FAILED


def _format_result(payload: dict[str, Any]) -> str:
    lines = [
        f"verification: {'VALID' if payload['valid'] else 'FAILED'}",
        f"  node     : {payload['node_id']}",
        f"  sequence : {payload['sequence']}",
        f"  key      : {payload['key_id']}",
        f"  hash     : {payload['event_hash']}",
    ]
    if payload["errors"]:
        lines.append("  errors:")
        lines.extend(f"    {alert}" for alert in payload["errors"])
    if payload["warnings"]:
        lines.append("  warnings:")
        lines.extend(f"    {alert}" for alert in payload["warnings"])
    if payload["details"]:
        lines.append("  details:")
        lines.extend(f"    {detail}" for detail in payload["details"])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# archives
# ---------------------------------------------------------------------------


def cmd_create_archive(args: argparse.Namespace) -> int:
    """Encrypt an evidence log into an offline archive."""
    registry = None
    if args.require_valid_evidence:
        if not args.registry:
            _fail(
                "--require-valid-evidence needs --registry: signatures cannot be "
                "verified without the trusted public keys",
                args.json,
                "usage",
            )
            return EXIT_USAGE
        try:
            registry = KeyRegistry.load(args.registry)
        except KeyRegistryError as exc:
            _fail(str(exc), args.json, "registry")
            return EXIT_USAGE

    try:
        public_key = load_public_key_file(args.recipient_public_key)
        manifest, trust = create_archive(
            evidence_path=args.input,
            archive_path=args.output,
            recipient_public_key=public_key,
            node_id=args.node_id,
            key_id=args.key_id or "",
            registry=registry,
            require_valid_evidence=args.require_valid_evidence,
            overwrite=args.force,
        )
    except (ArchiveError, EvidenceError, BackendError) as exc:
        _fail(str(exc), args.json, getattr(exc, "code", "archive"))
        return EXIT_VERIFICATION_FAILED if args.require_valid_evidence else EXIT_USAGE

    payload = {
        "ok": True,
        "archive": str(args.output),
        "manifest": manifest.to_dict(),
        "trust": trust.to_dict(),
    }
    _emit(
        payload,
        args.json,
        f"created archive {args.output}\n"
        f"  node       : {manifest.node_id}\n"
        f"  sequences  : {manifest.first_sequence}..{manifest.last_sequence} "
        f"({manifest.event_count} event(s))\n"
        f"  algorithms : {manifest.kem_algorithm} + {manifest.kdf_algorithm} + "
        f"{manifest.aead_algorithm}\n"
        f"  evidence strictly verified: {manifest.evidence_strictly_verified}",
    )
    return EXIT_OK


def cmd_decrypt_archive(args: argparse.Namespace) -> int:
    """Decrypt an archive back to a plaintext evidence log."""
    try:
        private_key = load_private_key(
            args.recipient_private_key, require_strict_permissions=not args.force
        )
        manifest, written, trust = decrypt_archive(
            archive_path=args.input,
            recipient_private_key=private_key,
            output_path=args.output,
            overwrite=args.force,
        )
    except (ArchiveError, EvidenceError, BackendError) as exc:
        _fail(str(exc), args.json, getattr(exc, "code", "archive"))
        return EXIT_VERIFICATION_FAILED

    payload = {
        "ok": True,
        "output": str(written) if written else None,
        "plaintext_bytes": manifest.plaintext_length,
        "manifest": manifest.to_dict(),
        "trust": trust.to_dict(),
    }
    _emit(
        payload,
        args.json,
        f"decrypted {args.input}"
        + (f" -> {written}" if written else "")
        + f"\n  {manifest.event_count} event(s), {manifest.plaintext_length} byte(s)"
        + "\n  container authenticated: yes (this does NOT mean the enclosed"
        + " records are genuine evidence; verify them with verify-log)",
    )
    return EXIT_OK


def cmd_verify_archive(args: argparse.Namespace) -> int:
    """Check an archive's structure and, with a key, its authentication."""
    private_key = None
    if args.recipient_private_key:
        try:
            private_key = load_private_key(
                args.recipient_private_key, require_strict_permissions=not args.force
            )
        except SignerError as exc:
            _fail(str(exc), args.json, "io")
            return EXIT_IO

    registry = None
    if args.registry:
        try:
            registry = KeyRegistry.load(args.registry)
        except KeyRegistryError as exc:
            _fail(str(exc), args.json, "registry")
            return EXIT_USAGE

    report = verify_archive(args.input, private_key, registry=registry)
    trust = report["trust"]
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"archive: {report['archive']}")
        print(f"  structure valid              : {report['structure_valid']}")
        print(f"  container authenticated      : {trust['container_authenticated']}")
        print(f"  plaintext hash verified      : {trust['plaintext_hash_verified']}")
        print(f"  evidence format valid        : {trust['evidence_format_valid']}")
        print(f"  evidence signatures verified : {trust['evidence_signatures_verified']}")
        print(f"  evidence chain verified      : {trust['evidence_chain_verified']}")
        print(f"  node identity verified       : {trust['node_identity_verified']}")
        print(f"  FULLY VERIFIED               : {trust['fully_verified']}")
        for warning in trust["warnings"]:
            print(f"  warning: {warning}")
        for error in trust["errors"]:
            print(f"  [{error['code']}] {error['detail']}")

    if not report["structure_valid"] or trust["errors"]:
        return EXIT_VERIFICATION_FAILED
    if private_key is not None and not trust["container_authenticated"]:
        return EXIT_VERIFICATION_FAILED
    if registry is not None and not trust["fully_verified"]:
        return EXIT_VERIFICATION_FAILED
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    """Show chain state without exposing any key material."""
    try:
        signer = _build_signer(args)
        status = signer.status()
    except BackendUnavailableError as exc:
        _fail(exc.detail, args.json, "no_backend")
        return EXIT_NO_BACKEND
    except EvidenceError as exc:
        _fail(str(exc), args.json, "status")
        return EXIT_IO

    _emit(
        status,
        args.json,
        f"node {status['node_id']}\n"
        f"  last sequence   : {status['last_sequence']}\n"
        f"  last event hash : {status['last_event_hash']}\n"
        f"  evidence log    : {status['evidence_log']} ({status['evidence_bytes']} bytes)\n"
        f"  pending journal : {status['journal_present']}\n"
        f"  backend         : {status['backend']} (real PQC: {status['real_pqc']})",
    )
    return EXIT_OK


def cmd_recover_state(args: argparse.Namespace) -> int:
    """Rebuild chain state from the evidence log. Explicit operator action."""
    if not args.confirm:
        _fail(
            "recover-state rewrites chain state from the evidence log. Inspect the log "
            "first, then re-run with --confirm.",
            args.json,
            "usage",
        )
        return EXIT_USAGE
    try:
        signer = _build_signer(args)
        repaired = signer.repair_state_from_log()
    except BackendUnavailableError as exc:
        _fail(exc.detail, args.json, "no_backend")
        return EXIT_NO_BACKEND
    except EvidenceError as exc:
        _fail(str(exc), args.json, "recover")
        return EXIT_IO

    _emit(
        {"ok": True, "state": repaired},
        args.json,
        f"state repaired from the evidence log\n"
        f"  last sequence   : {repaired['last_sequence']}\n"
        f"  last event hash : {repaired['last_event_hash']}",
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Run the reproducible PQC benchmark suite."""
    from ics_deception.pqc_evidence.benchmark import run_benchmarks, write_csv

    try:
        report = run_benchmarks(
            backend_name=args.backend,
            algorithm=args.algorithm,
            iterations=args.iterations,
            chain_events=args.chain_events,
            include_archive=not args.no_archive,
            allow_test_backend=args.allow_test_backend,
        )
    except BackendUnavailableError as exc:
        _fail(exc.detail, args.json, "no_backend")
        return EXIT_NO_BACKEND
    except EvidenceError as exc:
        _fail(str(exc), args.json, "benchmark")
        return EXIT_USAGE

    if args.output:
        try:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        except OSError as exc:
            _fail(f"cannot write {args.output}: {exc}", args.json, "io")
            return EXIT_IO
    if args.csv:
        try:
            write_csv(report, args.csv)
        except OSError as exc:
            _fail(f"cannot write {args.csv}: {exc}", args.json, "io")
            return EXIT_IO

    if args.json or not args.output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        environment = report["environment"]
        print(f"benchmark complete on {environment['platform']}")
        print(f"  backend : {environment['backend']} ({environment['backend_provider']})")
        for measurement in report["measurements"]:
            if measurement.get("mean_ms"):
                print(
                    f"  {measurement['name']:32s} "
                    f"{measurement['mean_ms']:9.3f} ms  "
                    f"{measurement['ops_per_second']:10.1f} ops/s"
                )
        print(f"  results written to {args.output}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the complete argument parser."""
    parser = argparse.ArgumentParser(
        prog="ics-pqc-evidence",
        description=(
            "Post-quantum digital seal for honeypot logs. Signs events into a "
            "SHA3-256 hash chain with ML-DSA-65 so that modification, deletion, "
            "reordering and replay become detectable. This is NOT TLS and does "
            "not encrypt any protocol traffic. Authorized laboratory use only."
        ),
        epilog="Exit codes: 0 ok, 1 verification failed, 2 usage, 3 no backend, 4 I/O.",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    parser.add_argument(
        "--allow-test-backend",
        action="store_true",
        help=f"permit the {TEST_BACKEND!r} backend (NO SECURITY; tests only)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_backend_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--backend", default=None, help="force a crypto backend by name")
        sub.add_argument(
            "--algorithm",
            default=DEFAULT_SIGNATURE_ALGORITHM,
            help=f"signature algorithm (default: {DEFAULT_SIGNATURE_ALGORITHM})",
        )

    def add_registry_option(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--registry",
            default=DEFAULT_REGISTRY,
            help=f"trusted public key registry (default: {DEFAULT_REGISTRY})",
        )

    def add_signer_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--node-id", required=True, help="identity of the signing node")
        sub.add_argument("--key-id", required=True, help="identifier of the signing key")
        sub.add_argument("--private-key", required=True, help="path to the node private key")
        sub.add_argument(
            "--state", default=DEFAULT_STATE, help=f"chain state file (default: {DEFAULT_STATE})"
        )
        sub.add_argument(
            "--force", action="store_true", help="relax permission checks / allow overwrite"
        )

    # capabilities
    sub = subparsers.add_parser(
        "capabilities", help="report available cryptographic backends and algorithms"
    )
    sub.set_defaults(func=cmd_capabilities)

    # generate-key
    sub = subparsers.add_parser("generate-key", help="generate a node ML-DSA signing key pair")
    add_backend_options(sub)
    sub.add_argument("--private-key", required=True, help="where to write the private key (0600)")
    sub.add_argument("--public-key", default=None, help="where to write the base64 public key")
    sub.add_argument("--force", action="store_true", help="overwrite an existing private key")
    sub.set_defaults(func=cmd_generate_key)

    # register-key
    sub = subparsers.add_parser("register-key", help="add a public key to the trusted registry")
    add_registry_option(sub)
    sub.add_argument("--node-id", required=True, help="node the key belongs to")
    sub.add_argument("--key-id", required=True, help="identifier for the key")
    sub.add_argument("--public-key", required=True, help="path to the base64 or raw public key")
    sub.add_argument(
        "--algorithm", default=DEFAULT_SIGNATURE_ALGORITHM, help="signature algorithm"
    )
    sub.add_argument(
        "--activated-at",
        default=None,
        help="UTC time the key became valid (needed to verify pre-existing logs)",
    )
    sub.add_argument("--expires-at", default=None, help="UTC expiry time, if any")
    sub.add_argument(
        "--inactive", action="store_true", help="register without making it the active key"
    )
    sub.set_defaults(func=cmd_register_key)

    # rotate-key
    sub = subparsers.add_parser("rotate-key", help="switch a node to a new active key")
    add_registry_option(sub)
    sub.add_argument("--node-id", required=True)
    sub.add_argument("--key-id", required=True, help="identifier of the NEW key")
    sub.add_argument("--public-key", required=True, help="path to the new public key")
    sub.add_argument("--algorithm", default=DEFAULT_SIGNATURE_ALGORITHM)
    sub.set_defaults(func=cmd_rotate_key)

    # revoke-key
    sub = subparsers.add_parser("revoke-key", help="revoke a key so its events stop being trusted")
    add_registry_option(sub)
    sub.add_argument("--key-id", required=True)
    sub.add_argument("--reason", required=True, help="why the key is being revoked")
    sub.set_defaults(func=cmd_revoke_key)

    # sign-event
    sub = subparsers.add_parser("sign-event", help="sign one JSON event")
    add_backend_options(sub)
    add_signer_options(sub)
    sub.add_argument("--event", default="-", help="event JSON file, or '-' for stdin")
    sub.add_argument("--output", default=None, help="evidence log to append to")
    sub.add_argument(
        "--print-record", action="store_true", help="also print the signed record to stdout"
    )
    sub.set_defaults(func=cmd_sign_event)

    # sign-log
    sub = subparsers.add_parser("sign-log", help="sign every JSON line of a log")
    add_backend_options(sub)
    add_signer_options(sub)
    sub.add_argument("--input", default="-", help="unsigned JSONL file, or '-' for stdin")
    sub.add_argument("--output", required=True, help="signed evidence JSONL file")
    sub.add_argument(
        "--max-events", type=positive_int, default=None, help="stop after N events (must be > 0)"
    )
    sub.set_defaults(func=cmd_sign_log)

    # verify-event
    sub = subparsers.add_parser("verify-event", help="verify one signed evidence record")
    add_registry_option(sub)
    sub.add_argument("--event", default="-", help="evidence JSON file, or '-' for stdin")
    sub.set_defaults(func=cmd_verify_event)

    # verify-log
    sub = subparsers.add_parser("verify-log", help="verify a signed evidence log and its chain")
    add_registry_option(sub)
    sub.add_argument("--input", default="-", help="evidence JSONL file, or '-' for stdin")
    sub.add_argument(
        "--include-results", action="store_true", help="include per-record results in JSON output"
    )
    sub.set_defaults(func=cmd_verify_log)

    # create-archive
    sub = subparsers.add_parser("create-archive", help="encrypt evidence into an offline archive")
    sub.add_argument("--input", required=True, help="signed evidence JSONL file")
    sub.add_argument("--output", required=True, help="archive file to create")
    sub.add_argument(
        "--recipient-public-key", required=True, help="raw or base64 ML-KEM-768 public key"
    )
    sub.add_argument("--node-id", required=True)
    sub.add_argument("--key-id", default=None)
    sub.add_argument(
        "--registry", default=None, help="trusted public keys, required for strict mode"
    )
    sub.add_argument(
        "--require-valid-evidence",
        action="store_true",
        help=(
            "strict mode: refuse to archive unless every record parses, its ML-DSA "
            "signature verifies, the chain is continuous and all records belong to "
            "one trusted node"
        ),
    )
    sub.add_argument("--force", action="store_true", help="overwrite an existing archive")
    sub.set_defaults(func=cmd_create_archive)

    # decrypt-archive
    sub = subparsers.add_parser("decrypt-archive", help="decrypt an evidence archive")
    sub.add_argument("--input", required=True, help="archive file")
    sub.add_argument("--output", default=None, help="where to write the plaintext evidence")
    sub.add_argument("--recipient-private-key", required=True, help="ML-KEM-768 private key")
    sub.add_argument("--force", action="store_true", help="overwrite output / relax key mode check")
    sub.set_defaults(func=cmd_decrypt_archive)

    # verify-archive
    sub = subparsers.add_parser("verify-archive", help="check an archive's integrity")
    sub.add_argument("--input", required=True, help="archive file")
    sub.add_argument(
        "--recipient-private-key",
        default=None,
        help="optional key; without it only the container and manifest are checked",
    )
    sub.add_argument(
        "--registry",
        default=None,
        help="trusted public keys; without it the enclosed evidence is NOT verified",
    )
    sub.add_argument("--force", action="store_true", help="relax key permission checks")
    sub.set_defaults(func=cmd_verify_archive)

    # status
    sub = subparsers.add_parser("status", help="show a node's chain state and any pending journal")
    add_backend_options(sub)
    add_signer_options(sub)
    sub.add_argument("--evidence", default=None, help="signed evidence JSONL file to inspect")
    sub.set_defaults(func=cmd_status)

    # recover-state
    sub = subparsers.add_parser(
        "recover-state",
        help="administrative repair: rebuild chain state from the evidence log",
    )
    add_backend_options(sub)
    add_signer_options(sub)
    sub.add_argument("--evidence", default=None, help="signed evidence JSONL file to repair from")
    sub.add_argument(
        "--confirm",
        action="store_true",
        help="required: confirms you have inspected the log and accept the repair",
    )
    sub.set_defaults(func=cmd_recover_state)

    # benchmark
    sub = subparsers.add_parser("benchmark", help="measure PQC performance on this machine")
    add_backend_options(sub)
    sub.add_argument(
        "--iterations", type=positive_int, default=20, help="repetitions per operation (> 0)"
    )
    sub.add_argument(
        "--chain-events", type=positive_int, default=200, help="events in the chain test (> 0)"
    )
    sub.add_argument("--no-archive", action="store_true", help="skip ML-KEM and archive benchmarks")
    sub.add_argument("--output", default=None, help="write the JSON report here")
    sub.add_argument("--csv", default=None, help="also write measurements as CSV")
    sub.set_defaults(func=cmd_benchmark)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``ics-pqc-evidence``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BackendUnavailableError as exc:
        _fail(exc.detail, getattr(args, "json", False), "no_backend")
        return EXIT_NO_BACKEND
    except EvidenceError as exc:
        _fail(str(exc), getattr(args, "json", False), "evidence")
        return EXIT_USAGE
    except BrokenPipeError:  # pragma: no cover - piping into head(1)
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return EXIT_IO


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
