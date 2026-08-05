"""Encrypted forensic archives: trust semantics, tamper detection, streaming."""

from __future__ import annotations

import json
import os
import resource
import stat
import zipfile

import pytest

from ics_deception.pqc_evidence.archive import (
    ARCHIVE_FORMAT_VERSION,
    CHUNK_BYTES,
    ArchiveError,
    ArchiveManifest,
    create_archive,
    decrypt_archive,
    verify_archive,
)
from ics_deception.pqc_evidence.key_registry import KeyRegistry
from tests.pqc_evidence.conftest import KEY_ID, NODE_ID

pytestmark = pytest.mark.pqc


@pytest.fixture
def evidence_file(tmp_path, signed_lines):
    path = tmp_path / "signed.jsonl"
    path.write_text("\n".join(signed_lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def archive(tmp_path, evidence_file, kem_keypair, kem_backend):
    path = tmp_path / "evidence.pqcarch"
    create_archive(
        evidence_file,
        path,
        kem_keypair.public_bytes,
        node_id=NODE_ID,
        key_id=KEY_ID,
        backend=kem_backend,
    )
    return path


def parts(archive_path):
    with zipfile.ZipFile(archive_path) as container:
        return json.loads(container.read("manifest.json")), container.read("evidence.bin")


def rebuild(path, manifest, ciphertext, extra=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as container:
        container.writestr(
            "manifest.json",
            manifest if isinstance(manifest, (str, bytes)) else json.dumps(manifest, indent=2),
        )
        container.writestr("evidence.bin", ciphertext)
        if extra:
            container.writestr(*extra)
    return path


# ===========================================================================
# Round trip
# ===========================================================================


def test_round_trip_recovers_the_original_bytes(
    archive, evidence_file, kem_keypair, kem_backend, tmp_path
):
    output = tmp_path / "restored.jsonl"

    manifest, written, trust = decrypt_archive(
        archive, kem_keypair.private_bytes, output_path=output, backend=kem_backend
    )

    assert written == output
    assert output.read_bytes() == evidence_file.read_bytes()
    assert trust.container_authenticated is True
    assert trust.plaintext_hash_verified is True
    assert manifest.node_id == NODE_ID
    assert manifest.event_count == 5


def test_the_manifest_records_the_expected_metadata(archive, kem_keypair, kem_backend):
    manifest, _, _ = decrypt_archive(archive, kem_keypair.private_bytes, backend=kem_backend)

    assert manifest.archive_format_version == ARCHIVE_FORMAT_VERSION
    assert manifest.kem_algorithm == "ML-KEM-768"
    assert manifest.kdf_algorithm == "HKDF-SHA-256"
    assert manifest.aead_algorithm == "AES-256-GCM"
    assert manifest.first_sequence == 1
    assert manifest.last_sequence == 5
    assert len(manifest.plaintext_sha3_256) == 64


def test_the_manifest_carries_no_duplicate_auth_tag(archive):
    """The tag lives with the ciphertext only.

    A duplicated copy in the manifest was never compared against the real tag,
    so editing it was silently ignored — worse than useless.
    """
    manifest, _ = parts(archive)

    assert "auth_tag" not in manifest
    assert "auth_tag" not in ArchiveManifest.__dataclass_fields__


def test_the_plaintext_is_not_recoverable_without_the_key(archive, evidence_file):
    raw = archive.read_bytes()

    assert b"modbus_honeypot" not in raw
    assert evidence_file.read_bytes()[:80] not in raw


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_the_archive_is_owner_only(archive):
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600


# ===========================================================================
# Trust semantics: container authentication is not evidence verification
# ===========================================================================


def test_container_authentication_is_reported_separately_from_evidence(
    archive, kem_keypair, registry
):
    without = verify_archive(archive, kem_keypair.private_bytes)
    with_registry = verify_archive(archive, kem_keypair.private_bytes, registry=registry)

    # Authenticated container, but nothing said about the enclosed records.
    assert without["trust"]["container_authenticated"] is True
    assert without["trust"]["evidence_signatures_verified"] is False
    assert without["trust"]["fully_verified"] is False
    assert any("not verified" in w for w in without["trust"]["warnings"])

    # With a registry the evidence itself is checked.
    assert with_registry["trust"]["evidence_signatures_verified"] is True
    assert with_registry["trust"]["evidence_chain_verified"] is True
    assert with_registry["trust"]["node_identity_verified"] is True
    assert with_registry["trust"]["fully_verified"] is True


def test_an_archive_of_unsigned_json_authenticates_but_does_not_verify(
    tmp_path, kem_keypair, kem_backend, registry
):
    """The crucial distinction: AES-GCM says nothing about what is inside."""
    fake = tmp_path / "fake.jsonl"
    fake.write_text('{"source":"modbus","event_type":"totally made up"}\n', encoding="utf-8")
    path = tmp_path / "fake.pqcarch"
    create_archive(fake, path, kem_keypair.public_bytes, node_id=NODE_ID, backend=kem_backend)

    report = verify_archive(path, kem_keypair.private_bytes, registry=registry)

    assert report["trust"]["container_authenticated"] is True
    assert report["trust"]["evidence_format_valid"] is False
    assert report["trust"]["fully_verified"] is False


def test_strict_mode_rejects_unsigned_evidence(tmp_path, kem_keypair, kem_backend, registry):
    fake = tmp_path / "fake.jsonl"
    fake.write_text('{"not":"evidence"}\n', encoding="utf-8")

    with pytest.raises(ArchiveError) as excinfo:
        create_archive(
            fake,
            tmp_path / "out.pqcarch",
            kem_keypair.public_bytes,
            node_id=NODE_ID,
            backend=kem_backend,
            registry=registry,
            require_valid_evidence=True,
        )
    assert excinfo.value.code == "evidence_rejected"
    assert not (tmp_path / "out.pqcarch").exists()


def test_strict_mode_accepts_genuine_evidence(
    tmp_path, evidence_file, kem_keypair, kem_backend, registry
):
    manifest, trust = create_archive(
        evidence_file,
        tmp_path / "strict.pqcarch",
        kem_keypair.public_bytes,
        node_id=NODE_ID,
        key_id=KEY_ID,
        backend=kem_backend,
        registry=registry,
        require_valid_evidence=True,
    )

    assert manifest.evidence_strictly_verified is True
    assert trust.evidence_signatures_verified is True
    assert trust.evidence_chain_verified is True


def test_strict_mode_rejects_a_tampered_record(
    tmp_path, signed_lines, kem_keypair, kem_backend, registry
):
    tampered = json.loads(signed_lines[2])
    tampered["event"]["username"] = "Admin"
    lines = signed_lines[:2] + [json.dumps(tampered, separators=(",", ":"), sort_keys=True)]
    path = tmp_path / "tampered.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ArchiveError, match="strict mode refused"):
        create_archive(
            path,
            tmp_path / "out.pqcarch",
            kem_keypair.public_bytes,
            node_id=NODE_ID,
            backend=kem_backend,
            registry=registry,
            require_valid_evidence=True,
        )


def test_strict_mode_rejects_a_mixed_node_log(
    tmp_path, signed_lines, signing_keypair, other_keypair, pqc_backend, kem_keypair, kem_backend
):
    from ics_deception.pqc_evidence.signer import EvidenceSigner

    other = EvidenceSigner(
        "another-node",
        "another-node-k1",
        other_keypair.private_bytes,
        tmp_path / "other-state.json",
        tmp_path / "other-evidence.jsonl",
        backend=pqc_backend,
    )
    foreign = other.sign_event({"source": "s", "event_type": "elsewhere"}).to_json_line()

    registry = KeyRegistry()
    registry.register(KEY_ID, NODE_ID, signing_keypair.public_bytes,
                      activated_at="2000-01-01T00:00:00Z")
    registry.register("another-node-k1", "another-node", other_keypair.public_bytes,
                      activated_at="2000-01-01T00:00:00Z")

    mixed = tmp_path / "mixed.jsonl"
    mixed.write_text("\n".join([*signed_lines, foreign]) + "\n", encoding="utf-8")

    with pytest.raises(ArchiveError, match="strict mode refused"):
        create_archive(
            mixed,
            tmp_path / "out.pqcarch",
            kem_keypair.public_bytes,
            node_id=NODE_ID,
            backend=kem_backend,
            registry=registry,
            require_valid_evidence=True,
        )


def test_strict_mode_requires_a_registry(tmp_path, evidence_file, kem_keypair, kem_backend):
    with pytest.raises(ArchiveError, match="requires a trusted-node registry"):
        create_archive(
            evidence_file,
            tmp_path / "out.pqcarch",
            kem_keypair.public_bytes,
            node_id=NODE_ID,
            backend=kem_backend,
            require_valid_evidence=True,
        )


def test_strict_mode_rejects_a_node_id_that_does_not_match(
    tmp_path, evidence_file, kem_keypair, kem_backend, registry
):
    with pytest.raises(ArchiveError, match="does not match the evidence"):
        create_archive(
            evidence_file,
            tmp_path / "out.pqcarch",
            kem_keypair.public_bytes,
            node_id="a-different-node",
            backend=kem_backend,
            registry=registry,
            require_valid_evidence=True,
        )


# ===========================================================================
# Manifest binding: every field is AAD
# ===========================================================================


PROTECTED_FIELDS = [
    ("node_id", "attacker-node"),
    ("key_id", "attacker-key"),
    ("first_sequence", 999),
    ("last_sequence", 999),
    ("event_count", 1),
    ("created_at", "2000-01-01T00:00:00.000000Z"),
    ("chain_final_hash", "0" * 64),
    ("plaintext_sha3_256", "0" * 64),
    ("plaintext_length", 1),
    ("encapsulated_key", None),
    ("hkdf_salt", None),
    ("nonce", None),
    ("evidence_strictly_verified", True),
    ("metadata", {"injected": "value"}),
]


@pytest.mark.parametrize(("field", "value"), PROTECTED_FIELDS)
def test_modifying_any_protected_manifest_field_fails_verification(
    archive, tmp_path, kem_keypair, kem_backend, field, value
):
    manifest, ciphertext = parts(archive)
    if value is None:
        import base64

        original = base64.b64decode(manifest[field])
        flipped = bytearray(original)
        flipped[0] ^= 0x01
        manifest[field] = base64.b64encode(bytes(flipped)).decode()
    else:
        manifest[field] = value
    target = rebuild(tmp_path / "bad.pqcarch", manifest, ciphertext)

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code in ("authentication_failed", "bad_manifest", "truncated")


def test_modifying_the_ciphertext_length_is_detected(archive, tmp_path, kem_keypair, kem_backend):
    manifest, ciphertext = parts(archive)
    manifest["ciphertext_length"] = manifest["ciphertext_length"] + 1
    target = rebuild(tmp_path / "bad.pqcarch", manifest, ciphertext)

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code == "truncated"


def test_adding_an_auth_tag_field_to_the_manifest_is_rejected(
    archive, tmp_path, kem_keypair, kem_backend
):
    """The field no longer exists, so re-introducing one is an unknown field."""
    manifest, ciphertext = parts(archive)
    manifest["auth_tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    target = rebuild(tmp_path / "bad.pqcarch", manifest, ciphertext)

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code == "bad_manifest"


def test_modified_ciphertext_is_detected(archive, tmp_path, kem_keypair, kem_backend):
    manifest, ciphertext = parts(archive)
    corrupted = bytearray(ciphertext)
    corrupted[10] ^= 0x01
    target = rebuild(tmp_path / "bad.pqcarch", manifest, bytes(corrupted))

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code == "authentication_failed"


def test_a_modified_tag_is_detected(archive, tmp_path, kem_keypair, kem_backend):
    manifest, ciphertext = parts(archive)
    corrupted = bytearray(ciphertext)
    corrupted[-1] ^= 0xFF
    target = rebuild(tmp_path / "bad.pqcarch", manifest, bytes(corrupted))

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code == "authentication_failed"


def test_the_wrong_private_key_fails_authentication(archive, kem_backend, kem_keypair):
    other = kem_backend.kem_generate_keypair("ML-KEM-768")

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(archive, other.private_bytes, backend=kem_backend)
    assert excinfo.value.code == "authentication_failed"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("archive_format_version", "9.9"),
        ("kem_algorithm", "ML-KEM-512"),
        ("kdf_algorithm", "PBKDF2"),
        ("aead_algorithm", "AES-128-CBC"),
    ],
)
def test_unsupported_algorithm_identifiers_are_refused(
    archive, tmp_path, kem_keypair, kem_backend, field, value
):
    manifest, ciphertext = parts(archive)
    manifest[field] = value
    target = rebuild(tmp_path / "bad.pqcarch", manifest, ciphertext)

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code in ("unsupported_version", "unsupported_algorithm")


# ===========================================================================
# Container validation
# ===========================================================================


def test_an_unexpected_entry_is_refused(archive, tmp_path, kem_keypair, kem_backend):
    manifest, ciphertext = parts(archive)
    target = rebuild(
        tmp_path / "bad.pqcarch", manifest, ciphertext, extra=("../evil.sh", "rm -rf /")
    )

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code in ("unexpected_entry", "path_traversal")


def test_a_missing_entry_is_refused(archive, tmp_path, kem_keypair, kem_backend):
    manifest, _ = parts(archive)
    target = tmp_path / "partial.pqcarch"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as container:
        container.writestr("manifest.json", json.dumps(manifest))

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)
    assert excinfo.value.code == "truncated"


def test_a_truncated_archive_is_detected(archive, tmp_path, kem_keypair, kem_backend):
    target = tmp_path / "truncated.pqcarch"
    target.write_bytes(archive.read_bytes()[:150])

    with pytest.raises(ArchiveError):
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)


def test_a_non_zip_file_is_refused(tmp_path, kem_keypair, kem_backend):
    target = tmp_path / "not.pqcarch"
    target.write_bytes(b"this is not a zip archive at all")

    with pytest.raises(ArchiveError):
        decrypt_archive(target, kem_keypair.private_bytes, backend=kem_backend)


# ===========================================================================
# Limits and resource usage
# ===========================================================================


@pytest.mark.parametrize("limit", [0, -1])
def test_non_positive_limits_are_rejected(archive, kem_keypair, kem_backend, limit):
    with pytest.raises(ArchiveError, match="must be a positive integer"):
        decrypt_archive(
            archive, kem_keypair.private_bytes, backend=kem_backend, max_archive_bytes=limit
        )


def test_an_oversized_input_is_refused(tmp_path, evidence_file, kem_keypair, kem_backend):
    with pytest.raises(ArchiveError) as excinfo:
        create_archive(
            evidence_file,
            tmp_path / "out.pqcarch",
            kem_keypair.public_bytes,
            node_id=NODE_ID,
            backend=kem_backend,
            max_plaintext_bytes=10,
        )
    assert excinfo.value.code == "oversized"


def test_an_oversized_archive_is_refused(archive, kem_keypair, kem_backend):
    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(
            archive, kem_keypair.private_bytes, backend=kem_backend, max_archive_bytes=10
        )
    assert excinfo.value.code == "oversized"


def test_a_decompression_bomb_is_refused(tmp_path, kem_keypair, kem_backend):
    """A tiny ciphertext that expands enormously must be stopped mid-stream."""
    source = tmp_path / "big.jsonl"
    source.write_bytes(b"\x00" * (8 * 1024 * 1024))
    target = tmp_path / "bomb.pqcarch"
    create_archive(source, target, kem_keypair.public_bytes, node_id=NODE_ID, backend=kem_backend)

    with pytest.raises(ArchiveError) as excinfo:
        decrypt_archive(
            target, kem_keypair.private_bytes, backend=kem_backend, max_plaintext_bytes=4096
        )
    assert excinfo.value.code == "decompression_bomb"


def test_a_large_archive_stays_within_a_bounded_memory_target(
    tmp_path, kem_keypair, kem_backend
):
    """Peak RSS must not grow with file size: everything is chunked.

    Writes a file several times the chunk size and asserts the process does not
    grow by anything close to it.
    """
    payload_size = 24 * CHUNK_BYTES  # 24 MiB
    source = tmp_path / "large.jsonl"
    line = json.dumps({"filler": "x" * 512}) + "\n"
    with open(source, "w", encoding="utf-8") as handle:
        written = 0
        while written < payload_size:
            handle.write(line)
            written += len(line)

    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    target = tmp_path / "large.pqcarch"
    create_archive(
        source,
        target,
        kem_keypair.public_bytes,
        node_id=NODE_ID,
        backend=kem_backend,
        max_plaintext_bytes=payload_size * 2,
    )
    restored = tmp_path / "restored.jsonl"
    decrypt_archive(
        target,
        kem_keypair.private_bytes,
        output_path=restored,
        backend=kem_backend,
        max_plaintext_bytes=payload_size * 2,
    )
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # Compare by streaming digest: read_bytes() on both files would itself pull
    # 48 MiB into this process and make the memory assertion meaningless.
    def digest_of(path):
        import hashlib

        hasher = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
        return hasher.hexdigest()

    assert digest_of(restored) == digest_of(source)
    growth_bytes = max(0, after - before) * 1024
    assert growth_bytes < payload_size, (
        f"peak RSS grew by {growth_bytes} bytes for a {payload_size} byte file; "
        "the archive path is not streaming"
    )


# ===========================================================================
# Failure cleanup
# ===========================================================================


def test_a_failed_decryption_writes_no_plaintext(archive, tmp_path, kem_backend, kem_keypair):
    """Unauthenticated plaintext must never reach the destination."""
    other = kem_backend.kem_generate_keypair("ML-KEM-768")
    output = tmp_path / "should-not-exist.jsonl"

    with pytest.raises(ArchiveError):
        decrypt_archive(
            archive, other.private_bytes, output_path=output, backend=kem_backend
        )

    assert not output.exists(), "unauthenticated plaintext was written to the destination"
    strays = [p.name for p in tmp_path.iterdir() if p.name.startswith(".ics-pqc-plain-")]
    assert strays == [], f"temporary plaintext left behind: {strays}"


def test_a_failed_creation_leaves_no_partial_archive(
    tmp_path, evidence_file, kem_keypair, kem_backend
):
    target = tmp_path / "out.pqcarch"
    with pytest.raises(ArchiveError):
        create_archive(
            evidence_file,
            target,
            kem_keypair.public_bytes,
            node_id=NODE_ID,
            backend=kem_backend,
            max_plaintext_bytes=10,
        )

    assert not target.exists()
    assert not (tmp_path / "out.pqcarch.tmp").exists()


def test_a_failed_verification_preserves_the_original_archive(
    archive, kem_backend, kem_keypair
):
    before = archive.read_bytes()
    other = kem_backend.kem_generate_keypair("ML-KEM-768")

    report = verify_archive(archive, other.private_bytes)

    assert report["trust"]["container_authenticated"] is False
    assert archive.read_bytes() == before, "the archive was modified by a failed verification"


def test_creating_over_an_existing_archive_is_refused(
    archive, evidence_file, kem_keypair, kem_backend
):
    with pytest.raises(ArchiveError, match="refusing to overwrite"):
        create_archive(
            evidence_file, archive, kem_keypair.public_bytes, node_id=NODE_ID, backend=kem_backend
        )


# ===========================================================================
# verify_archive reporting
# ===========================================================================


def test_verify_archive_without_a_key_checks_structure_only(archive):
    report = verify_archive(archive)

    assert report["structure_valid"] is True
    assert report["trust"]["container_authenticated"] is False
    assert report["trust"]["warnings"]


def test_verify_archive_detects_a_manifest_content_mismatch(
    tmp_path, evidence_file, kem_keypair, kem_backend, registry
):
    """The manifest must describe the evidence it actually holds."""
    path = tmp_path / "lying.pqcarch"
    create_archive(
        evidence_file,
        path,
        kem_keypair.public_bytes,
        node_id="a-node-that-did-not-sign-this",
        backend=kem_backend,
    )

    report = verify_archive(path, kem_keypair.private_bytes, registry=registry)

    assert report["trust"]["container_authenticated"] is True
    assert report["trust"]["node_identity_verified"] is False
    assert any(e["code"] == "manifest_content_mismatch" for e in report["trust"]["errors"])


def test_manifest_rejects_unknown_fields():
    with pytest.raises(ArchiveError, match="unknown field"):
        ArchiveManifest.from_dict({"archive_format_version": ARCHIVE_FORMAT_VERSION, "extra": 1})
