"""Trusted-node registry: lifecycle, rotation, persistence and import/export."""

from __future__ import annotations

import json
import os
import stat

import pytest

from ics_deception.pqc_evidence.key_registry import (
    KeyRegistry,
    KeyRegistryError,
    KeyState,
    fingerprint,
    load_public_key_file,
)

pytestmark = pytest.mark.pqc

NODE = "rpi-honeypot-01"


@pytest.fixture
def keys(pqc_backend):
    """Three distinct public keys."""
    return [pqc_backend.generate_keypair("ML-DSA-65").public_bytes for _ in range(3)]


# -- registration -----------------------------------------------------------


def test_registering_a_key_makes_it_active(keys):
    registry = KeyRegistry()
    record = registry.register("k1", NODE, keys[0])

    assert record.state is KeyState.ACTIVE
    assert registry.active_key(NODE).key_id == "k1"
    assert len(registry) == 1


def test_a_registered_key_reports_a_fingerprint(keys):
    registry = KeyRegistry()
    record = registry.register("k1", NODE, keys[0])

    assert record.fingerprint == fingerprint(keys[0])
    assert len(record.public_key_sha3_256) == 64
    assert record.public_key_bytes == keys[0]


def test_reusing_a_key_id_for_a_different_key_is_rejected(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])

    with pytest.raises(KeyRegistryError, match="conflicting definitions"):
        registry.register("k1", NODE, keys[1])


def test_registering_the_same_record_twice_is_rejected(keys):
    from ics_deception.pqc_evidence.key_registry import KeyRecord

    registry = KeyRegistry()
    record = registry.register("k1", NODE, keys[0])
    duplicate = KeyRecord.from_dict(record.to_dict())

    with pytest.raises(KeyRegistryError, match="duplicate key_id"):
        KeyRegistry([record, duplicate])


def test_registering_the_same_public_key_twice_is_rejected(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])

    with pytest.raises(KeyRegistryError, match="already registered"):
        registry.register("k2", "another-node", keys[0])


def test_an_unsupported_algorithm_is_rejected(keys):
    registry = KeyRegistry()

    with pytest.raises(KeyRegistryError, match="unsupported algorithm"):
        registry.register("k1", NODE, keys[0], algorithm="RSA-4096")


def test_an_empty_public_key_is_rejected():
    registry = KeyRegistry()

    with pytest.raises(KeyRegistryError, match="must not be empty"):
        registry.register("k1", NODE, b"")


def test_multiple_nodes_are_tracked_independently(keys):
    registry = KeyRegistry()
    registry.register("a1", "node-a", keys[0])
    registry.register("b1", "node-b", keys[1])

    assert registry.nodes() == ["node-a", "node-b"]
    assert registry.active_key("node-a").key_id == "a1"
    assert registry.active_key("node-b").key_id == "b1"


# -- lifecycle --------------------------------------------------------------


def test_rotation_marks_the_old_key_rotated_and_the_new_one_active(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])

    registry.rotate(NODE, "k2", keys[1])

    assert registry.get("k1").state is KeyState.ROTATED
    assert registry.get("k2").state is KeyState.ACTIVE
    assert registry.active_key(NODE).key_id == "k2"


def test_rotation_keeps_the_historical_key_available(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0], activated_at="2000-01-01T00:00:00Z")
    registry.rotate(NODE, "k2", keys[1])

    usability = registry.check_usable("k1", NODE, "2020-01-01T00:00:00Z", "ML-DSA-65")

    assert usability.usable, "a rotated key must still verify historical events"


def test_rotating_a_node_with_no_keys_is_refused(keys):
    registry = KeyRegistry()

    with pytest.raises(KeyRegistryError, match="no registered key"):
        registry.rotate(NODE, "k1", keys[0])


def test_multiple_historical_keys_are_kept(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])
    registry.rotate(NODE, "k2", keys[1])
    registry.rotate(NODE, "k3", keys[2])

    assert len(registry.for_node(NODE)) == 3
    assert registry.active_key(NODE).key_id == "k3"


def test_revocation_requires_a_reason(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])

    with pytest.raises(KeyRegistryError, match="reason is required"):
        registry.revoke("k1", "   ")


def test_revocation_records_reason_and_time(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])

    record = registry.revoke("k1", "host compromised")

    assert record.state is KeyState.REVOKED
    assert record.revocation_reason == "host compromised"
    assert record.revoked_at


def test_revoking_an_unknown_key_is_refused():
    with pytest.raises(KeyRegistryError, match="unknown key_id"):
        KeyRegistry().revoke("absent", "reason")


# -- usability checks -------------------------------------------------------


def test_usable_key_reports_no_problems(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0], activated_at="2000-01-01T00:00:00Z")

    usability = registry.check_usable("k1", NODE, "2026-08-05T18:15:00Z", "ML-DSA-65")

    assert usability.usable
    assert usability.problems == ()


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        (lambda r: r.revoke("k1", "compromised"), "pqc_revoked_key"),
        (lambda r: r.disable("k1"), "pqc_revoked_key"),
    ],
)
def test_state_problems_are_reported(keys, setup, expected):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0], activated_at="2000-01-01T00:00:00Z")
    setup(registry)

    usability = registry.check_usable("k1", NODE, "2026-08-05T18:15:00Z", "ML-DSA-65")

    assert expected in usability.problems


def test_expiry_is_enforced(keys):
    registry = KeyRegistry()
    registry.register(
        "k1",
        NODE,
        keys[0],
        activated_at="2000-01-01T00:00:00Z",
        expires_at="2001-01-01T00:00:00Z",
    )

    assert "pqc_expired_key" in registry.check_usable(
        "k1", NODE, "2026-08-05T18:15:00Z", "ML-DSA-65"
    ).problems
    assert registry.check_usable("k1", NODE, "2000-06-01T00:00:00Z", "ML-DSA-65").usable


def test_activation_is_enforced(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0], activated_at="2026-01-01T00:00:00Z")

    early = registry.check_usable("k1", NODE, "2020-01-01T00:00:00Z", "ML-DSA-65")

    assert not early.usable
    assert "precedes key activation" in early.detail


def test_an_unknown_node_and_key_are_both_reported(keys):
    usability = KeyRegistry().check_usable("k1", NODE, "2026-08-05T18:15:00Z", "ML-DSA-65")

    assert "pqc_unknown_node" in usability.problems
    assert "pqc_unknown_key" in usability.problems


def test_a_node_key_mismatch_is_reported(keys):
    registry = KeyRegistry()
    registry.register("k1", "node-a", keys[0], activated_at="2000-01-01T00:00:00Z")

    usability = registry.check_usable("k1", "node-b", "2026-08-05T18:15:00Z", "ML-DSA-65")

    assert "pqc_unknown_node" in usability.problems


# -- persistence ------------------------------------------------------------


def test_save_and_load_round_trip(tmp_path, keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])
    registry.rotate(NODE, "k2", keys[1])
    registry.revoke("k1", "rotated out and revoked")
    path = registry.save(tmp_path / "registry.json")

    loaded = KeyRegistry.load(path)

    assert len(loaded) == 2
    assert loaded.get("k1").state is KeyState.REVOKED
    assert loaded.get("k1").revocation_reason == "rotated out and revoked"
    assert loaded.active_key(NODE).key_id == "k2"


def test_saving_is_atomic_and_leaves_no_temporary_files(tmp_path, keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])

    registry.save(tmp_path / "registry.json")

    assert [p.name for p in tmp_path.iterdir()] == ["registry.json"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_the_registry_file_is_not_writable_by_others(tmp_path, keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])
    path = registry.save(tmp_path / "registry.json")

    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & (stat.S_IWGRP | stat.S_IWOTH)


def test_loading_a_missing_registry_yields_an_empty_one(tmp_path):
    assert len(KeyRegistry.load(tmp_path / "absent.json")) == 0


def test_loading_malformed_json_is_refused(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text("{ not json", encoding="utf-8")

    with pytest.raises(KeyRegistryError, match="not valid JSON"):
        KeyRegistry.load(path)


def test_loading_an_unsupported_version_is_refused(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"format_version": "9.9", "keys": []}), encoding="utf-8")

    with pytest.raises(KeyRegistryError, match="unsupported registry format_version"):
        KeyRegistry.load(path)


def test_loading_a_record_with_a_bad_public_key_is_refused(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "format_version": "1.0",
                "keys": [
                    {
                        "key_id": "k1",
                        "node_id": NODE,
                        "algorithm": "ML-DSA-65",
                        "public_key": "not base64!!",
                        "created_at": "2026-01-01T00:00:00.000000Z",
                        "activated_at": "2026-01-01T00:00:00.000000Z",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(KeyRegistryError):
        KeyRegistry.load(path)


# -- import / export --------------------------------------------------------


def test_export_contains_only_public_material(keys):
    registry = KeyRegistry()
    registry.register("k1", NODE, keys[0])

    document = registry.export_public()
    text = json.dumps(document)

    assert "private" not in text.lower()
    assert document["keys"][0]["public_key"]


def test_import_merges_new_entries(keys):
    source = KeyRegistry()
    source.register("k1", NODE, keys[0])
    source.register("k2", "node-b", keys[1])

    target = KeyRegistry()
    added = target.import_public(source.export_public())

    assert sorted(added) == ["k1", "k2"]
    assert len(target) == 2


def test_import_skips_existing_entries_by_default(keys):
    source = KeyRegistry()
    source.register("k1", NODE, keys[0])
    target = KeyRegistry()
    target.import_public(source.export_public())

    added = target.import_public(source.export_public())

    assert added == []
    assert len(target) == 1


def test_import_rejects_a_bad_document():
    with pytest.raises(KeyRegistryError):
        KeyRegistry().import_public({"format_version": "0.1", "keys": []})


# -- public key files -------------------------------------------------------


def test_a_base64_public_key_file_loads(tmp_path, keys):
    import base64

    path = tmp_path / "node.pub"
    path.write_text(base64.b64encode(keys[0]).decode() + "\n", encoding="utf-8")

    assert load_public_key_file(path) == keys[0]


def test_a_raw_public_key_file_loads(tmp_path, keys):
    path = tmp_path / "node.raw"
    path.write_bytes(keys[0])

    assert load_public_key_file(path) == keys[0]


def test_a_missing_public_key_file_is_refused(tmp_path):
    from ics_deception.pqc_evidence.models import EvidenceValidationError

    with pytest.raises(EvidenceValidationError, match="not found"):
        load_public_key_file(tmp_path / "absent.pub")


def test_an_empty_public_key_file_is_refused(tmp_path):
    from ics_deception.pqc_evidence.models import EvidenceValidationError

    path = tmp_path / "empty.pub"
    path.touch()

    with pytest.raises(EvidenceValidationError, match="empty"):
        load_public_key_file(path)
