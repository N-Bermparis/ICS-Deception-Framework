"""Optional encrypted forensic archives.

Signing makes tampering *detectable*. Archiving makes a body of evidence
*confidential* while it is moved or stored offline — a separate, optional
concern, deliberately not part of routine event signing.

Construction
------------
::

    ML-KEM-768   →  shared secret (32 bytes)
    HKDF-SHA-256 →  AES-256 key (32 bytes)   [salt = random 32 B, info = context]
    AES-256-GCM  →  encrypt gzip(evidence.jsonl), streamed in chunks

ML-KEM is **not** used to encrypt the evidence directly: a KEM establishes a
shared secret, and a symmetric AEAD does the bulk encryption. That is KEM/DEM
composition, and treating a KEM as public-key encryption is a classic misuse.

Where the authentication tag lives
----------------------------------
In **exactly one** place: appended to the ciphertext in ``evidence.bin``, where
AES-GCM put it. The manifest does *not* carry a copy.

An earlier version stored the tag in the manifest as well. That was worse than
redundant — the manifest copy was never compared against the real tag, so
editing it was silently ignored, which invites a reader to trust a value that
means nothing. One tag, one location, no ambiguity.

What the manifest *is* protected by
-----------------------------------
The canonical JSON of the whole manifest is passed to AES-GCM as **additional
authenticated data**. Every field — archive version, node id, key id, sequence
range, event count, creation time, chain hash, plaintext hash and length,
algorithm identifiers, encapsulated key, salt, nonce, ciphertext length — is
cryptographically bound to the ciphertext. Change any one of them and
decryption fails with an authentication error.

The exact AAD bytes are ``canonical_bytes(manifest.to_dict())`` where the dict
excludes nothing, because there is no longer a tag field to exclude.

Container
---------
A ZIP holding exactly two stored (uncompressed) entries: ``manifest.json`` and
``evidence.bin``. Reading rejects unexpected names, duplicate names, absolute or
traversing paths, oversized members and gzip bombs.

Trust vocabulary
----------------
"Verified" is never used loosely. :class:`ArchiveTrust` reports six independent
facts, and container authentication is not evidence validity:

``container_authenticated``   AES-GCM authenticated the ciphertext and manifest.
``plaintext_hash_verified``   The recovered bytes match the manifest digest.
``evidence_format_valid``     Every line parses as a signed-event envelope.
``evidence_signatures_verified`` Every ML-DSA signature verifies.
``evidence_chain_verified``   Sequences and previous-hashes form one chain.
``node_identity_verified``    Every record belongs to the manifest's node and key.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import gzip
import hashlib
import json
import os
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from ics_deception.pqc_evidence import EvidenceError
from ics_deception.pqc_evidence.canonicalizer import canonical_bytes
from ics_deception.pqc_evidence.crypto_backend import CryptoBackend, select_backend

__all__ = [
    "ARCHIVE_FORMAT_VERSION",
    "ArchiveError",
    "ArchiveManifest",
    "ArchiveTrust",
    "create_archive",
    "decrypt_archive",
    "verify_archive",
]

#: Version of the archive container and manifest.
ARCHIVE_FORMAT_VERSION = "2.0"

KEM_ALGORITHM = "ML-KEM-768"
KDF_ALGORITHM = "HKDF-SHA-256"
AEAD_ALGORITHM = "AES-256-GCM"

MANIFEST_ENTRY = "manifest.json"
CIPHERTEXT_ENTRY = "evidence.bin"
_EXPECTED_ENTRIES = frozenset({MANIFEST_ENTRY, CIPHERTEXT_ENTRY})

#: HKDF context string, bound into the derived key.
HKDF_INFO = b"ics-deception/pqc-evidence/archive/v2"

#: Chunk size for streaming hash, compress, encrypt and decrypt.
CHUNK_BYTES = 1024 * 1024

#: Conservative defaults, sized for a Raspberry Pi rather than a workstation.
#: Both are configurable per call; neither may be zero or negative.
DEFAULT_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_PLAINTEXT_BYTES = 256 * 1024 * 1024

MAX_MANIFEST_BYTES = 64 * 1024
GCM_TAG_BYTES = 16
GCM_NONCE_BYTES = 12
HKDF_SALT_BYTES = 32


class ArchiveError(EvidenceError):
    """An archive could not be created, read or authenticated."""

    def __init__(self, message: str, code: str = "archive_error") -> None:
        super().__init__(message)
        self.code = code


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: Any, field_name: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise ArchiveError(f"manifest field {field_name} must be a base64 string", "bad_manifest")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ArchiveError(
            f"manifest field {field_name} is not valid base64: {exc}", "bad_manifest"
        ) from exc


def _positive(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ArchiveError(f"{name} must be a positive integer, got {value!r}", "bad_limit")
    return value


def _hkdf_sha256(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF with SHA-256, on hmac/hashlib.

    Written out rather than pulled from a library so the archive format has one
    fewer moving dependency; it is a dozen lines and directly checkable against
    the RFC test vectors.
    """
    import hmac

    if length > 255 * 32:
        raise ArchiveError("HKDF output length is too large", "internal_error")
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _aesgcm_streaming(key: bytes, nonce: bytes, aad: bytes, encrypt: bool):
    """Return a streaming AES-256-GCM context.

    ``cryptography``'s one-shot ``AESGCM`` would require the whole plaintext in
    memory, which is exactly what this module must avoid. The lower-level
    ``Cipher`` interface supports incremental ``update()``.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ArchiveError(
            "AES-256-GCM requires the 'cryptography' package; "
            "install with: pip install 'ics-deception[pqc]'",
            "missing_dependency",
        ) from exc
    mode = modes.GCM(nonce) if encrypt else modes.GCM(nonce, None)
    cipher = Cipher(algorithms.AES(key), mode)
    context = cipher.encryptor() if encrypt else cipher.decryptor()
    context.authenticate_additional_data(aad)
    return context


@dataclass
class ArchiveManifest:
    """Metadata describing one encrypted archive.

    Every field here is authenticated: the canonical form of this whole object
    is the AES-GCM additional authenticated data. There is deliberately **no**
    ``auth_tag`` field — the tag lives with the ciphertext and nowhere else.
    """

    archive_format_version: str
    node_id: str
    key_id: str
    first_sequence: int
    last_sequence: int
    event_count: int
    created_at: str
    chain_final_hash: str
    plaintext_sha3_256: str
    plaintext_length: int
    kem_algorithm: str
    kdf_algorithm: str
    aead_algorithm: str
    encapsulated_key: str
    hkdf_salt: str
    nonce: str
    ciphertext_length: int
    #: True when creation verified every enclosed record against a registry.
    evidence_strictly_verified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the manifest as a plain dict."""
        return asdict(self)

    def authenticated_data(self) -> bytes:
        """The exact bytes bound into AES-GCM as additional authenticated data.

        Canonical JSON of the entire manifest. Nothing is excluded, so every
        field is covered and there is no "unauthenticated corner" to hide in.
        """
        return canonical_bytes(self.to_dict())

    @staticmethod
    def from_dict(data: Any) -> ArchiveManifest:
        """Validate an untrusted manifest."""
        if not isinstance(data, dict):
            raise ArchiveError("manifest must be a JSON object", "bad_manifest")

        expected = set(ArchiveManifest.__dataclass_fields__)
        unknown = set(data) - expected
        if unknown:
            raise ArchiveError(
                f"manifest has unknown field(s): {sorted(unknown)}", "bad_manifest"
            )
        optional = {"metadata", "evidence_strictly_verified"}
        missing = expected - set(data) - optional
        if missing:
            raise ArchiveError(f"manifest is missing field(s): {sorted(missing)}", "bad_manifest")

        if data.get("archive_format_version") != ARCHIVE_FORMAT_VERSION:
            raise ArchiveError(
                f"unsupported archive_format_version {data.get('archive_format_version')!r}; "
                f"expected {ARCHIVE_FORMAT_VERSION!r}",
                "unsupported_version",
            )
        for name, expected_value in (
            ("kem_algorithm", KEM_ALGORITHM),
            ("kdf_algorithm", KDF_ALGORITHM),
            ("aead_algorithm", AEAD_ALGORITHM),
        ):
            if data.get(name) != expected_value:
                raise ArchiveError(
                    f"unsupported {name} {data.get(name)!r}; this build only supports "
                    f"{expected_value!r}",
                    "unsupported_algorithm",
                )
        for name in (
            "first_sequence",
            "last_sequence",
            "event_count",
            "ciphertext_length",
            "plaintext_length",
        ):
            value = data.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ArchiveError(
                    f"manifest field {name} must be a non-negative integer", "bad_manifest"
                )
        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ArchiveError("manifest metadata must be an object", "bad_manifest")
        strict = data.get("evidence_strictly_verified", False)
        if not isinstance(strict, bool):
            raise ArchiveError(
                "manifest evidence_strictly_verified must be a boolean", "bad_manifest"
            )

        return ArchiveManifest(
            **{**data, "metadata": metadata, "evidence_strictly_verified": strict}
        )


@dataclass
class ArchiveTrust:
    """Six independent facts about an archive. None of them implies another."""

    container_authenticated: bool = False
    plaintext_hash_verified: bool = False
    evidence_format_valid: bool = False
    evidence_signatures_verified: bool = False
    evidence_chain_verified: bool = False
    node_identity_verified: bool = False
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def fully_verified(self) -> bool:
        """True only when *every* check passed. Never inferred from one of them."""
        return all(
            (
                self.container_authenticated,
                self.plaintext_hash_verified,
                self.evidence_format_valid,
                self.evidence_signatures_verified,
                self.evidence_chain_verified,
                self.node_identity_verified,
            )
        )

    def fail(self, code: str, detail: str) -> None:
        """Record a failure."""
        self.errors.append({"code": code, "detail": detail})

    def to_dict(self) -> dict[str, Any]:
        """Return the structured trust report."""
        return {
            "container_authenticated": self.container_authenticated,
            "plaintext_hash_verified": self.plaintext_hash_verified,
            "evidence_format_valid": self.evidence_format_valid,
            "evidence_signatures_verified": self.evidence_signatures_verified,
            "evidence_chain_verified": self.evidence_chain_verified,
            "node_identity_verified": self.node_identity_verified,
            "fully_verified": self.fully_verified,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "details": dict(self.details),
        }


# ---------------------------------------------------------------------------
# Evidence inspection (used by strict creation and by verification)
# ---------------------------------------------------------------------------


def summarise_evidence(
    path: Path,
    registry: Any | None = None,
    strict: bool = False,
    max_record_bytes: int | None = None,
) -> tuple[dict[str, Any], ArchiveTrust]:
    """Scan an evidence file, optionally verifying every record.

    Without a registry this only extracts the sequence range and count — enough
    to fill the manifest, and explicitly *not* a claim that the contents are
    genuine. With ``strict``, every record must parse, verify and chain.
    """
    trust = ArchiveTrust()
    first: int | None = None
    last: int | None = None
    final_hash = ""
    count = 0
    nodes: set[str] = set()
    keys: set[str] = set()

    if strict and registry is None:
        raise ArchiveError(
            "strict mode requires a trusted-node registry to verify signatures against",
            "registry_required",
        )

    collector = None
    if registry is not None:
        from ics_deception.pqc_evidence.collector import EvidenceCollector
        from ics_deception.pqc_evidence.models import MAX_EVIDENCE_BYTES

        collector = EvidenceCollector(
            registry, max_record_bytes=max_record_bytes or MAX_EVIDENCE_BYTES
        )

    # Deliberately does not accumulate the lines: an earlier version built a
    # list of every record, which pulled a whole multi-gigabyte evidence file
    # into memory before a single byte was encrypted. The file is cheap to read
    # twice and constant in memory.
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            text = raw.strip()
            if not text:
                continue
            count += 1
            try:
                record = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                if strict:
                    trust.fail(
                        "unparsable_record",
                        f"record {count} is not valid JSON; strict mode requires signed evidence",
                    )
                continue
            if not isinstance(record, dict):
                if strict:
                    trust.fail("unparsable_record", f"record {count} is not a JSON object")
                continue
            sequence = record.get("sequence")
            if isinstance(sequence, int) and not isinstance(sequence, bool):
                first = sequence if first is None else min(first, sequence)
                last = sequence if last is None else max(last, sequence)
            event_hash = record.get("event_hash")
            if isinstance(event_hash, str):
                final_hash = event_hash
            if isinstance(record.get("node_id"), str):
                nodes.add(record["node_id"])
            if isinstance(record.get("key_id"), str):
                keys.add(record["key_id"])

    summary = {
        "first_sequence": first or 0,
        "last_sequence": last or 0,
        "event_count": count,
        "chain_final_hash": final_hash,
        "nodes": sorted(nodes),
        "key_ids": sorted(keys),
    }

    if collector is None:
        return summary, trust

    def stream_lines():
        """Second pass, streamed: never holds more than one line."""
        with open(path, encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                text = raw.strip()
                if text:
                    yield text

    report = collector.verify_stream(stream_lines())
    trust.details["verification"] = {
        "total": report.total,
        "verified": report.verified,
        "failed": report.failed,
        "malformed": report.malformed,
        "alerts": dict(report.alert_counts),
    }
    trust.evidence_format_valid = report.malformed == 0 and report.total > 0
    signature_alerts = {"pqc_invalid_signature", "pqc_unknown_key", "pqc_unknown_node",
                        "pqc_revoked_key", "pqc_expired_key", "pqc_unsupported_algorithm"}
    chain_alerts = {"pqc_sequence_gap", "pqc_previous_hash_mismatch", "pqc_duplicate_sequence",
                    "pqc_replayed_event", "pqc_chain_reset", "pqc_event_hash_mismatch"}
    trust.evidence_signatures_verified = not (signature_alerts & set(report.alert_counts))
    trust.evidence_chain_verified = not (chain_alerts & set(report.alert_counts))
    trust.node_identity_verified = len(nodes) == 1 and len(keys) >= 1

    if strict:
        if report.total == 0:
            trust.fail("empty_evidence", "strict mode requires at least one signed record")
        if report.malformed:
            trust.fail(
                "malformed_evidence",
                f"{report.malformed} record(s) are not valid signed evidence",
            )
        if report.failed:
            trust.fail(
                "invalid_evidence",
                f"{report.failed} record(s) failed verification: "
                f"{sorted(report.alert_counts)}",
            )
        if len(nodes) > 1:
            trust.fail(
                "mixed_node_log",
                f"evidence contains records from {len(nodes)} nodes ({sorted(nodes)}); "
                "a single-node archive cannot represent that",
            )
    return summary, trust


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


def create_archive(
    evidence_path: str | Path,
    archive_path: str | Path,
    recipient_public_key: bytes,
    node_id: str,
    key_id: str = "",
    backend: CryptoBackend | None = None,
    registry: Any | None = None,
    require_valid_evidence: bool = False,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
    overwrite: bool = False,
    metadata: dict[str, Any] | None = None,
) -> tuple[ArchiveManifest, ArchiveTrust]:
    """Encrypt a signed-evidence JSONL file into an archive.

    With ``require_valid_evidence`` (strict mode) every enclosed record must
    parse, carry a verifying ML-DSA signature, chain correctly, and belong to a
    single node whose key the registry trusts. Unsigned or forged JSON is
    refused rather than sealed and later mistaken for evidence.

    Input is hashed, compressed and encrypted in :data:`CHUNK_BYTES` chunks, so
    peak memory does not scale with file size.
    """
    _positive(max_plaintext_bytes, "max_plaintext_bytes")
    source = Path(evidence_path).expanduser()
    target = Path(archive_path).expanduser()
    if not source.is_file():
        raise ArchiveError(f"evidence file not found: {source}", "not_found")
    if target.exists() and not overwrite:
        raise ArchiveError(
            f"refusing to overwrite {target}; pass overwrite=True if that is intended",
            "exists",
        )

    size = source.stat().st_size
    if size > max_plaintext_bytes:
        raise ArchiveError(
            f"evidence file is {size} bytes, exceeding the {max_plaintext_bytes} byte limit",
            "oversized",
        )

    summary, trust = summarise_evidence(
        source, registry=registry, strict=require_valid_evidence
    )
    if require_valid_evidence and trust.errors:
        raise ArchiveError(
            "strict mode refused this evidence: "
            + "; ".join(f"[{e['code']}] {e['detail']}" for e in trust.errors),
            "evidence_rejected",
        )
    if require_valid_evidence and summary["nodes"] and summary["nodes"][0] != node_id:
        raise ArchiveError(
            f"--node-id {node_id!r} does not match the evidence, which is from "
            f"{summary['nodes'][0]!r}",
            "node_mismatch",
        )

    kem = backend if backend is not None else select_backend(require_kem=KEM_ALGORITHM)
    shared_secret, encapsulated = kem.kem_encapsulate(recipient_public_key, KEM_ALGORITHM)
    salt = os.urandom(HKDF_SALT_BYTES)
    nonce = os.urandom(GCM_NONCE_BYTES)
    aes_key = _hkdf_sha256(shared_secret, salt, HKDF_INFO, 32)

    # Pass one: hash the plaintext and measure the compressed size, streaming.
    digest = hashlib.sha3_256()
    plaintext_length = 0
    workdir = tempfile.mkdtemp(prefix="ics-pqc-archive-")
    compressed_path = Path(workdir) / "compressed.gz"
    try:
        with open(source, "rb") as reader, gzip.GzipFile(
            filename="", mode="wb", fileobj=open(compressed_path, "wb"), compresslevel=6, mtime=0
        ) as writer:
            while True:
                chunk = reader.read(CHUNK_BYTES)
                if not chunk:
                    break
                plaintext_length += len(chunk)
                if plaintext_length > max_plaintext_bytes:
                    raise ArchiveError(
                        f"evidence exceeded the {max_plaintext_bytes} byte limit while reading",
                        "oversized",
                    )
                digest.update(chunk)
                writer.write(chunk)
        compressed_length = compressed_path.stat().st_size

        manifest = ArchiveManifest(
            archive_format_version=ARCHIVE_FORMAT_VERSION,
            node_id=node_id,
            key_id=key_id,
            first_sequence=summary["first_sequence"],
            last_sequence=summary["last_sequence"],
            event_count=summary["event_count"],
            created_at=_utc_now(),
            chain_final_hash=summary["chain_final_hash"],
            plaintext_sha3_256=digest.hexdigest(),
            plaintext_length=plaintext_length,
            kem_algorithm=KEM_ALGORITHM,
            kdf_algorithm=KDF_ALGORITHM,
            aead_algorithm=AEAD_ALGORITHM,
            encapsulated_key=_b64(encapsulated),
            hkdf_salt=_b64(salt),
            nonce=_b64(nonce),
            ciphertext_length=compressed_length + GCM_TAG_BYTES,
            evidence_strictly_verified=bool(require_valid_evidence),
            metadata=metadata or {},
        )

        # Pass two: encrypt the compressed stream in chunks.
        encryptor = _aesgcm_streaming(aes_key, nonce, manifest.authenticated_data(), encrypt=True)
        ciphertext_path = Path(workdir) / "ciphertext.bin"
        with open(compressed_path, "rb") as reader, open(ciphertext_path, "wb") as writer:
            while True:
                chunk = reader.read(CHUNK_BYTES)
                if not chunk:
                    break
                writer.write(encryptor.update(chunk))
            writer.write(encryptor.finalize())
            writer.write(encryptor.tag)  # the single authoritative tag
            writer.flush()
            os.fsync(writer.fileno())

        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        try:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(
                    MANIFEST_ENTRY, json.dumps(manifest.to_dict(), indent=2, sort_keys=True)
                )
                with open(ciphertext_path, "rb") as reader, archive.open(
                    CIPHERTEXT_ENTRY, "w"
                ) as entry:
                    while True:
                        chunk = reader.read(CHUNK_BYTES)
                        if not chunk:
                            break
                        entry.write(chunk)
            os.replace(temporary, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise
    finally:
        # Temporary plaintext and ciphertext are removed on success and failure.
        with contextlib.suppress(OSError):
            for leftover in Path(workdir).iterdir():
                leftover.unlink()
            os.rmdir(workdir)

    with contextlib.suppress(OSError):
        os.chmod(target, 0o600)
    trust.details["created"] = {"archive": str(target), "strict": bool(require_valid_evidence)}
    return manifest, trust


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _read_manifest_and_open_ciphertext(
    archive: zipfile.ZipFile, max_archive_bytes: int
) -> tuple[ArchiveManifest, zipfile.ZipInfo]:
    names = archive.namelist()
    if len(names) != len(set(names)):
        raise ArchiveError("archive contains duplicate entries", "duplicate_entry")
    unexpected = set(names) - _EXPECTED_ENTRIES
    if unexpected:
        raise ArchiveError(
            f"archive contains unexpected entries: {sorted(unexpected)}", "unexpected_entry"
        )
    missing = _EXPECTED_ENTRIES - set(names)
    if missing:
        raise ArchiveError(f"archive is missing entries: {sorted(missing)}", "truncated")
    for name in names:
        if name != os.path.basename(name) or name.startswith(("/", "\\")) or ".." in name:
            raise ArchiveError(
                f"archive entry {name!r} is not a plain file name", "path_traversal"
            )

    manifest_info = archive.getinfo(MANIFEST_ENTRY)
    if manifest_info.file_size > MAX_MANIFEST_BYTES:
        raise ArchiveError("archive manifest is implausibly large", "oversized")
    manifest_raw = archive.read(MANIFEST_ENTRY)
    try:
        manifest_data = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"archive manifest is not valid JSON: {exc}", "bad_manifest") from exc
    manifest = ArchiveManifest.from_dict(manifest_data)

    ciphertext_info = archive.getinfo(CIPHERTEXT_ENTRY)
    if ciphertext_info.file_size > max_archive_bytes:
        raise ArchiveError("archive payload exceeds the configured limit", "oversized")
    if ciphertext_info.file_size != manifest.ciphertext_length:
        raise ArchiveError(
            f"manifest declares {manifest.ciphertext_length} ciphertext bytes but the "
            f"archive holds {ciphertext_info.file_size}; it was truncated or altered",
            "truncated",
        )
    if ciphertext_info.file_size < GCM_TAG_BYTES:
        raise ArchiveError("archive payload is shorter than an AES-GCM tag", "truncated")
    return manifest, ciphertext_info


def _stream_decrypt(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    manifest: ArchiveManifest,
    aes_key: bytes,
    nonce: bytes,
    destination: BinaryIO,
    scratch_dir: Path,
    max_plaintext_bytes: int,
) -> tuple[int, str]:
    """Decrypt, authenticate, then decompress into ``destination``.

    Two streaming passes, in this order for a reason:

    1. Decrypt the ciphertext into a bounded temporary file and finalise the
       AES-GCM tag.
    2. **Only after authentication succeeds**, decompress that file.

    An AEAD cannot authenticate until it has seen everything, so a single-pass
    "decrypt and decompress as you go" design necessarily feeds *unauthenticated*
    bytes to the decompressor. That is an anti-pattern in its own right, and it
    also turns a tampered archive into a confusing ``zlib`` error instead of a
    clean authentication failure. Buffering the compressed intermediate — always
    smaller than the plaintext — is the right trade.

    Bomb protection is the absolute ``max_plaintext_bytes`` limit, enforced
    incrementally during decompression so a bomb aborts early rather than after
    filling the disk. A compressed-to-plaintext *ratio* guard was tried and
    removed: signed JSONL legitimately compresses by three orders of magnitude,
    so any ratio strict enough to catch a bomb also rejects real evidence.
    """
    import zlib

    body_length = info.file_size - GCM_TAG_BYTES
    decryptor = _aesgcm_streaming(aes_key, nonce, manifest.authenticated_data(), encrypt=False)

    fd, compressed_name = tempfile.mkstemp(prefix=".ics-pqc-ct-", dir=str(scratch_dir))
    os.close(fd)
    compressed_path = Path(compressed_name)
    os.chmod(compressed_path, 0o600)

    try:
        # Pass one: decrypt, then authenticate. Nothing is decompressed yet.
        with archive.open(info, "r") as reader, open(compressed_path, "wb") as writer:
            remaining = body_length
            while remaining > 0:
                chunk = reader.read(min(CHUNK_BYTES, remaining))
                if not chunk:
                    raise ArchiveError("archive payload ended early", "truncated")
                remaining -= len(chunk)
                writer.write(decryptor.update(chunk))
            tag = reader.read(GCM_TAG_BYTES)
            if len(tag) != GCM_TAG_BYTES:
                raise ArchiveError("archive is missing its authentication tag", "truncated")
            try:
                writer.write(decryptor.finalize_with_tag(tag))
            except Exception as exc:
                raise ArchiveError(
                    "archive authentication failed: wrong ML-KEM private key, modified "
                    "ciphertext, modified manifest or an incorrect AES-GCM tag",
                    "authentication_failed",
                ) from exc

        # Pass two: the bytes are authentic, so decompressing them is safe.
        digest = hashlib.sha3_256()
        written = 0
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        with open(compressed_path, "rb") as reader:
            while True:
                chunk = reader.read(CHUNK_BYTES)
                if not chunk:
                    break
                # ``max_length`` is capped at one chunk, not at the remaining
                # byte budget. Passing the whole budget lets zlib return tens of
                # megabytes from one small compressed chunk — the very
                # allocation this streaming path exists to avoid — and it is
                # also how a bomb would win. ``unconsumed_tail`` carries the
                # rest forward a chunk at a time.
                pending: bytes | None = chunk
                while pending is not None:
                    try:
                        data = decompressor.decompress(pending, CHUNK_BYTES)
                    except zlib.error as exc:
                        raise ArchiveError(
                            f"archive payload is not valid gzip data: {exc}", "corrupt"
                        ) from exc
                    if data:
                        written += len(data)
                        if written > max_plaintext_bytes:
                            raise ArchiveError(
                                f"decompressed evidence exceeds the {max_plaintext_bytes} "
                                "byte limit; the archive may be a decompression bomb",
                                "decompression_bomb",
                            )
                        digest.update(data)
                        destination.write(data)
                    pending = decompressor.unconsumed_tail or None
            try:
                tail = decompressor.flush()
            except zlib.error as exc:
                raise ArchiveError(
                    f"archive payload is not valid gzip data: {exc}", "corrupt"
                ) from exc
            if tail:
                written += len(tail)
                if written > max_plaintext_bytes:
                    raise ArchiveError(
                        f"decompressed evidence exceeds the {max_plaintext_bytes} byte limit; "
                        "the archive may be a decompression bomb",
                        "decompression_bomb",
                    )
                digest.update(tail)
                destination.write(tail)
        return written, digest.hexdigest()
    finally:
        with contextlib.suppress(OSError):
            os.unlink(compressed_path)


def decrypt_archive(
    archive_path: str | Path,
    recipient_private_key: bytes,
    output_path: str | Path | None = None,
    backend: CryptoBackend | None = None,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
    overwrite: bool = False,
) -> tuple[ArchiveManifest, Path | None, ArchiveTrust]:
    """Decrypt an archive, streaming the plaintext to a protected temporary file.

    Unauthenticated plaintext is **never** written to the caller's destination:
    output goes to a 0600 temporary file in the destination's directory and is
    renamed into place only after AES-GCM authentication and the digest check
    both succeed. On any failure the temporary file is removed and the original
    archive is left untouched.

    Returns ``(manifest, output_path_or_None, trust)``.
    """
    _positive(max_archive_bytes, "max_archive_bytes")
    _positive(max_plaintext_bytes, "max_plaintext_bytes")
    source = Path(archive_path).expanduser()
    if not source.is_file():
        raise ArchiveError(f"archive not found: {source}", "not_found")
    size = source.stat().st_size
    if size > max_archive_bytes:
        raise ArchiveError(
            f"archive is {size} bytes, exceeding the {max_archive_bytes} byte limit",
            "oversized",
        )

    trust = ArchiveTrust()
    destination = Path(output_path).expanduser() if output_path is not None else None
    if destination is not None and destination.exists() and not overwrite:
        raise ArchiveError(f"refusing to overwrite {destination}", "exists")

    scratch_dir = destination.parent if destination is not None else Path(tempfile.gettempdir())
    scratch_dir.mkdir(parents=True, exist_ok=True)
    fd, scratch_name = tempfile.mkstemp(prefix=".ics-pqc-plain-", dir=str(scratch_dir))
    os.close(fd)
    scratch = Path(scratch_name)
    os.chmod(scratch, 0o600)

    try:
        with zipfile.ZipFile(source) as archive:
            manifest, info = _read_manifest_and_open_ciphertext(archive, max_archive_bytes)

            kem = (
                backend
                if backend is not None
                else select_backend(
                    require_kem=KEM_ALGORITHM, for_private_key=recipient_private_key
                )
            )
            encapsulated = _unb64(manifest.encapsulated_key, "encapsulated_key")
            salt = _unb64(manifest.hkdf_salt, "hkdf_salt")
            nonce = _unb64(manifest.nonce, "nonce")
            if len(nonce) != GCM_NONCE_BYTES:
                raise ArchiveError(
                    f"nonce must be {GCM_NONCE_BYTES} bytes, got {len(nonce)}", "bad_manifest"
                )
            if len(salt) != HKDF_SALT_BYTES:
                raise ArchiveError(
                    f"hkdf_salt must be {HKDF_SALT_BYTES} bytes, got {len(salt)}", "bad_manifest"
                )

            # ML-KEM implicit rejection: a wrong key yields an unpredictable
            # secret rather than an error, so the mismatch surfaces below as an
            # AEAD authentication failure. That is by design, not a missing check.
            shared_secret = kem.kem_decapsulate(recipient_private_key, encapsulated, KEM_ALGORITHM)
            aes_key = _hkdf_sha256(shared_secret, salt, HKDF_INFO, 32)

            with open(scratch, "wb") as writer:
                written, digest = _stream_decrypt(
                    archive,
                    info,
                    manifest,
                    aes_key,
                    nonce,
                    writer,
                    scratch_dir,
                    max_plaintext_bytes,
                )
                writer.flush()
                os.fsync(writer.fileno())

        trust.container_authenticated = True

        if digest != manifest.plaintext_sha3_256 or written != manifest.plaintext_length:
            raise ArchiveError(
                "decrypted evidence does not match the manifest digest or length",
                "digest_mismatch",
            )
        trust.plaintext_hash_verified = True

        if destination is not None:
            os.replace(scratch, destination)
            os.chmod(destination, 0o600)
            scratch = None  # type: ignore[assignment]
            return manifest, destination, trust
        return manifest, None, trust
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"archive is corrupt or truncated: {exc}", "truncated") from exc
    finally:
        if scratch is not None:
            with contextlib.suppress(OSError):
                os.unlink(scratch)


def verify_archive(
    archive_path: str | Path,
    recipient_private_key: bytes | None = None,
    registry: Any | None = None,
    backend: CryptoBackend | None = None,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
) -> dict[str, Any]:
    """Report the six independent trust facts about an archive.

    * With no key: only the container structure and manifest are checked.
    * With a key: adds container authentication and the plaintext digest.
    * With a key **and** a registry: also parses and verifies every enclosed
      record, its signatures, its chain and its node identity.

    Container authentication alone never implies the contents are genuine
    evidence, and this report never conflates the two.
    """
    source = Path(archive_path).expanduser()
    trust = ArchiveTrust()
    report: dict[str, Any] = {"archive": str(source), "structure_valid": False, "manifest": None}

    try:
        with zipfile.ZipFile(source) as archive:
            manifest, _ = _read_manifest_and_open_ciphertext(archive, max_archive_bytes)
    except ArchiveError as exc:
        trust.fail(exc.code, str(exc))
        report["trust"] = trust.to_dict()
        return report
    except (zipfile.BadZipFile, OSError) as exc:
        trust.fail("truncated", f"archive is corrupt or unreadable: {exc}")
        report["trust"] = trust.to_dict()
        return report

    report["structure_valid"] = True
    report["manifest"] = manifest.to_dict()

    if recipient_private_key is None:
        trust.warnings.append(
            "no private key supplied: only the container structure and manifest were checked; "
            "this says nothing about whether the enclosed evidence is genuine"
        )
        report["trust"] = trust.to_dict()
        return report

    workdir = Path(tempfile.mkdtemp(prefix="ics-pqc-verify-"))
    plaintext = workdir / "evidence.jsonl"
    try:
        manifest, written, decrypt_trust = decrypt_archive(
            source,
            recipient_private_key,
            output_path=plaintext,
            backend=backend,
            max_archive_bytes=max_archive_bytes,
            max_plaintext_bytes=max_plaintext_bytes,
            overwrite=True,
        )
        trust.container_authenticated = decrypt_trust.container_authenticated
        trust.plaintext_hash_verified = decrypt_trust.plaintext_hash_verified

        if registry is None:
            trust.warnings.append(
                "no registry supplied: the enclosed records were not verified, so "
                "evidence validity is unknown"
            )
        elif written is not None:
            summary, evidence_trust = summarise_evidence(written, registry=registry, strict=False)
            trust.evidence_format_valid = evidence_trust.evidence_format_valid
            trust.evidence_signatures_verified = evidence_trust.evidence_signatures_verified
            trust.evidence_chain_verified = evidence_trust.evidence_chain_verified
            trust.details.update(evidence_trust.details)

            # The manifest must describe the evidence it actually contains.
            mismatches = []
            if summary["nodes"] and summary["nodes"] != [manifest.node_id]:
                mismatches.append(f"nodes {summary['nodes']} vs manifest {manifest.node_id!r}")
            if summary["event_count"] != manifest.event_count:
                mismatches.append(
                    f"event_count {summary['event_count']} vs manifest {manifest.event_count}"
                )
            if summary["first_sequence"] != manifest.first_sequence:
                mismatches.append("first_sequence mismatch")
            if summary["last_sequence"] != manifest.last_sequence:
                mismatches.append("last_sequence mismatch")
            if summary["chain_final_hash"] != manifest.chain_final_hash:
                mismatches.append("chain_final_hash mismatch")
            if mismatches:
                trust.fail("manifest_content_mismatch", "; ".join(mismatches))
                trust.node_identity_verified = False
            else:
                trust.node_identity_verified = (
                    len(summary["nodes"]) == 1 and summary["nodes"][0] == manifest.node_id
                )
    except ArchiveError as exc:
        trust.fail(exc.code, str(exc))
    finally:
        with contextlib.suppress(OSError):
            if plaintext.exists():
                plaintext.unlink()
            workdir.rmdir()

    report["trust"] = trust.to_dict()
    return report
