"""CLI behaviour: exit codes, JSON output, safe overwrite and secret hygiene."""

from __future__ import annotations

import base64
import json
import os

import pytest

from ics_deception.pqc_evidence.cli import (
    EXIT_NO_BACKEND,
    EXIT_OK,
    EXIT_USAGE,
    EXIT_VERIFICATION_FAILED,
    build_parser,
    main,
)

pytestmark = pytest.mark.pqc

NODE = "rpi-honeypot-01"
KEY = "rpi-honeypot-01-2026-01"


@pytest.fixture
def workspace(tmp_path, signing_keypair):
    """A ready-to-use key, registry and unsigned log."""
    private = tmp_path / "node.key"
    private.write_bytes(signing_keypair.private_bytes)
    private.chmod(0o600)
    public = tmp_path / "node.pub"
    public.write_text(base64.b64encode(signing_keypair.public_bytes).decode(), encoding="utf-8")

    raw = tmp_path / "raw.jsonl"
    raw.write_text(
        "\n".join(
            json.dumps({"source": "modbus_honeypot", "event_type": "modbus_request", "n": n})
            for n in range(3)
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "dir": tmp_path,
        "private": private,
        "public": public,
        "raw": raw,
        "registry": tmp_path / "registry.json",
        "state": tmp_path / "state.json",
        "evidence": tmp_path / "evidence.jsonl",
    }


def run(*argv: str) -> int:
    return main(list(argv))


# -- help and parser --------------------------------------------------------


def test_every_subcommand_has_help():
    parser = build_parser()
    subparsers = [
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    ]
    names = set(subparsers[0].choices)

    expected = {
        "capabilities",
        "generate-key",
        "register-key",
        "rotate-key",
        "revoke-key",
        "sign-event",
        "sign-log",
        "verify-event",
        "verify-log",
        "create-archive",
        "decrypt-archive",
        "verify-archive",
        "status",
        "recover-state",
        "benchmark",
    }
    assert expected <= names
    for name in expected:
        assert subparsers[0].choices[name].format_help()


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    assert "post-quantum" in capsys.readouterr().out.lower()


def test_no_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == EXIT_USAGE


# -- capabilities -----------------------------------------------------------


def test_capabilities_reports_a_real_backend(capsys):
    assert run("capabilities") == EXIT_OK
    assert "real PQC" in capsys.readouterr().out


def test_capabilities_json_is_machine_readable(capsys):
    assert run("--json", "capabilities") == EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["real_pqc_available"] is True
    assert payload["backends"]


# -- key management ---------------------------------------------------------


def test_generate_key_writes_both_halves(tmp_path, capsys):
    private = tmp_path / "new.key"

    assert run("generate-key", "--private-key", str(private)) == EXIT_OK

    assert private.is_file()
    assert (tmp_path / "new.pub").is_file()
    if os.name != "nt":  # Windows has no POSIX mode bits
        assert oct(private.stat().st_mode)[-3:] == "600"


def test_generate_key_never_prints_the_private_key(tmp_path, capsys, signing_keypair):
    private = tmp_path / "new.key"
    run("generate-key", "--private-key", str(private))

    output = capsys.readouterr().out
    secret = private.read_bytes()
    assert base64.b64encode(secret).decode()[:40] not in output
    assert secret.hex()[:40] not in output


def test_generate_key_refuses_to_clobber(tmp_path):
    private = tmp_path / "new.key"
    run("generate-key", "--private-key", str(private))

    assert run("generate-key", "--private-key", str(private)) == EXIT_USAGE


def test_register_and_rotate_and_revoke(workspace, capsys, other_keypair):
    registry = str(workspace["registry"])

    assert (
        run(
            "register-key",
            "--registry",
            registry,
            "--node-id",
            NODE,
            "--key-id",
            KEY,
            "--public-key",
            str(workspace["public"]),
            "--activated-at",
            "2000-01-01T00:00:00Z",
        )
        == EXIT_OK
    )

    second = workspace["dir"] / "second.pub"
    second.write_text(base64.b64encode(other_keypair.public_bytes).decode(), encoding="utf-8")
    assert (
        run(
            "rotate-key",
            "--registry",
            registry,
            "--node-id",
            NODE,
            "--key-id",
            f"{KEY}-v2",
            "--public-key",
            str(second),
        )
        == EXIT_OK
    )

    assert (
        run("revoke-key", "--registry", registry, "--key-id", KEY, "--reason", "seized")
        == EXIT_OK
    )

    from ics_deception.pqc_evidence.key_registry import KeyRegistry

    loaded = KeyRegistry.load(registry)
    assert loaded.get(KEY).state.value == "revoked"
    assert loaded.active_key(NODE).key_id == f"{KEY}-v2"


def test_revoking_an_unknown_key_is_a_usage_error(workspace):
    assert (
        run(
            "revoke-key",
            "--registry",
            str(workspace["registry"]),
            "--key-id",
            "absent",
            "--reason",
            "x",
        )
        == EXIT_USAGE
    )


# -- signing and verification ----------------------------------------------


def _register(workspace) -> None:
    run(
        "register-key",
        "--registry",
        str(workspace["registry"]),
        "--node-id",
        NODE,
        "--key-id",
        KEY,
        "--public-key",
        str(workspace["public"]),
        "--activated-at",
        "2000-01-01T00:00:00Z",
    )


def _sign(workspace) -> int:
    return run(
        "sign-log",
        "--node-id",
        NODE,
        "--key-id",
        KEY,
        "--private-key",
        str(workspace["private"]),
        "--state",
        str(workspace["state"]),
        "--input",
        str(workspace["raw"]),
        "--output",
        str(workspace["evidence"]),
    )


def test_sign_log_then_verify_log_succeeds(workspace):
    _register(workspace)
    assert _sign(workspace) == EXIT_OK

    assert (
        run(
            "verify-log",
            "--registry",
            str(workspace["registry"]),
            "--input",
            str(workspace["evidence"]),
        )
        == EXIT_OK
    )


def test_verify_log_fails_on_tampered_evidence(workspace):
    _register(workspace)
    _sign(workspace)
    text = workspace["evidence"].read_text(encoding="utf-8")
    workspace["evidence"].write_text(text.replace('"n":1', '"n":9'), encoding="utf-8")

    assert (
        run(
            "verify-log",
            "--registry",
            str(workspace["registry"]),
            "--input",
            str(workspace["evidence"]),
        )
        == EXIT_VERIFICATION_FAILED
    )


def test_verify_log_json_output_is_parseable(workspace, capsys):
    _register(workspace)
    _sign(workspace)
    capsys.readouterr()

    run(
        "--json",
        "verify-log",
        "--registry",
        str(workspace["registry"]),
        "--input",
        str(workspace["evidence"]),
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["verified"] == 3


def test_verify_event_handles_a_single_record(workspace, capsys):
    _register(workspace)
    _sign(workspace)
    first = workspace["evidence"].read_text(encoding="utf-8").splitlines()[0]
    single = workspace["dir"] / "one.json"
    single.write_text(first, encoding="utf-8")

    assert (
        run(
            "verify-event",
            "--registry",
            str(workspace["registry"]),
            "--event",
            str(single),
        )
        == EXIT_OK
    )


def test_sign_log_appends_to_an_existing_chain(workspace):
    """Appending is the normal case: a chain continues across runs.

    The signer owns the evidence log and appends transactionally, so continuing
    an existing chain is not an overwrite and needs no --force.
    """
    _register(workspace)
    assert _sign(workspace) == EXIT_OK
    first = workspace["evidence"].read_text(encoding="utf-8").strip().splitlines()

    assert _sign(workspace) == EXIT_OK
    second = workspace["evidence"].read_text(encoding="utf-8").strip().splitlines()

    assert len(second) == len(first) * 2
    sequences = [json.loads(line)["sequence"] for line in second]
    assert sequences == sorted(sequences) == list(range(1, len(second) + 1))


def test_a_missing_private_key_is_an_io_error(workspace):
    from ics_deception.pqc_evidence.cli import EXIT_IO

    assert (
        run(
            "sign-log",
            "--node-id",
            NODE,
            "--key-id",
            KEY,
            "--private-key",
            str(workspace["dir"] / "absent.key"),
            "--output",
            str(workspace["evidence"]),
        )
        == EXIT_IO
    )


def test_a_missing_evidence_file_is_a_usage_error(workspace):
    assert (
        run(
            "verify-log",
            "--registry",
            str(workspace["registry"]),
            "--input",
            str(workspace["dir"] / "absent.jsonl"),
        )
        == EXIT_USAGE
    )


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_non_positive_limits_are_rejected(workspace, value):
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "sign-log",
                "--node-id",
                NODE,
                "--key-id",
                KEY,
                "--private-key",
                str(workspace["private"]),
                "--output",
                str(workspace["evidence"]),
                "--max-events",
                value,
            ]
        )
    assert excinfo.value.code == EXIT_USAGE


def test_the_test_backend_needs_an_explicit_flag(workspace):
    assert (
        run(
            "generate-key",
            "--backend",
            "insecure-test-only",
            "--private-key",
            str(workspace["dir"] / "t.key"),
        )
        == EXIT_NO_BACKEND
    )


# -- archives ---------------------------------------------------------------


def test_archive_create_verify_decrypt_round_trip(workspace, kem_keypair, tmp_path):
    _register(workspace)
    _sign(workspace)

    kem_pub = tmp_path / "kem.pub"
    kem_pub.write_text(base64.b64encode(kem_keypair.public_bytes).decode(), encoding="utf-8")
    kem_priv = tmp_path / "kem.key"
    kem_priv.write_bytes(kem_keypair.private_bytes)
    kem_priv.chmod(0o600)
    archive = tmp_path / "evidence.pqcarch"

    assert (
        run(
            "create-archive",
            "--input",
            str(workspace["evidence"]),
            "--output",
            str(archive),
            "--recipient-public-key",
            str(kem_pub),
            "--node-id",
            NODE,
        )
        == EXIT_OK
    )
    assert (
        run("verify-archive", "--input", str(archive), "--recipient-private-key", str(kem_priv))
        == EXIT_OK
    )
    # With a registry the enclosed evidence is verified as well, not just the box.
    assert (
        run(
            "verify-archive",
            "--input",
            str(archive),
            "--recipient-private-key",
            str(kem_priv),
            "--registry",
            str(workspace["registry"]),
        )
        == EXIT_OK
    )

    restored = tmp_path / "restored.jsonl"
    assert (
        run(
            "decrypt-archive",
            "--input",
            str(archive),
            "--output",
            str(restored),
            "--recipient-private-key",
            str(kem_priv),
        )
        == EXIT_OK
    )
    assert restored.read_bytes() == workspace["evidence"].read_bytes()


def test_verify_archive_fails_on_a_tampered_archive(workspace, kem_keypair, tmp_path):
    import zipfile

    _register(workspace)
    _sign(workspace)
    kem_pub = tmp_path / "kem.pub"
    kem_pub.write_text(base64.b64encode(kem_keypair.public_bytes).decode(), encoding="utf-8")
    kem_priv = tmp_path / "kem.key"
    kem_priv.write_bytes(kem_keypair.private_bytes)
    kem_priv.chmod(0o600)
    archive = tmp_path / "evidence.pqcarch"
    run(
        "create-archive",
        "--input",
        str(workspace["evidence"]),
        "--output",
        str(archive),
        "--recipient-public-key",
        str(kem_pub),
        "--node-id",
        NODE,
    )

    with zipfile.ZipFile(archive) as container:
        manifest = container.read("manifest.json")
        payload = bytearray(container.read("evidence.bin"))
    payload[5] ^= 0x01
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as container:
        container.writestr("manifest.json", manifest)
        container.writestr("evidence.bin", bytes(payload))

    assert (
        run("verify-archive", "--input", str(archive), "--recipient-private-key", str(kem_priv))
        == EXIT_VERIFICATION_FAILED
    )


# -- benchmark --------------------------------------------------------------


def test_benchmark_writes_json_and_csv(tmp_path, capsys):
    report = tmp_path / "bench.json"
    csv_path = tmp_path / "bench.csv"

    assert (
        run(
            "benchmark",
            "--iterations",
            "2",
            "--chain-events",
            "5",
            "--no-archive",
            "--output",
            str(report),
            "--csv",
            str(csv_path),
        )
        == EXIT_OK
    )

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["environment"]["backend"] in ("openssl", "pyfips")
    assert payload["parameters"]["iterations"] == 2
    assert any(m["name"] == "mldsa_sign" for m in payload["measurements"])
    assert "mldsa_sign" in csv_path.read_text(encoding="utf-8")


def test_benchmark_output_contains_no_key_material(tmp_path):
    report = tmp_path / "bench.json"
    run(
        "benchmark",
        "--iterations",
        "1",
        "--chain-events",
        "2",
        "--no-archive",
        "--output",
        str(report),
    )

    text = report.read_text(encoding="utf-8").lower()
    assert "private" not in text or "private_key_bytes" in text
    assert "-----begin" not in text


# ===========================================================================
# status and recover-state
#
# These are the operator-facing halves of the transactional store: `status`
# says where a chain stands, `recover-state` is the one command allowed to
# rewrite chain state after an interrupted transaction. Both are documented in
# docs/pqc-evidence-architecture.md, so both need to keep working.
# ===========================================================================


def signer_args(workspace: dict) -> list[str]:
    return [
        "--node-id",
        NODE,
        "--key-id",
        KEY,
        "--private-key",
        str(workspace["private"]),
        "--state",
        str(workspace["state"]),
    ]


@pytest.fixture
def signed_workspace(workspace):
    """A workspace whose evidence log already holds three signed records."""
    assert (
        run(
            "sign-log",
            *signer_args(workspace),
            "--input",
            str(workspace["raw"]),
            "--output",
            str(workspace["evidence"]),
        )
        == EXIT_OK
    )
    return workspace


def test_status_reports_the_chain_position_without_key_material(signed_workspace, capsys):
    assert (
        run(
            "--json",
            "status",
            *signer_args(signed_workspace),
            "--evidence",
            str(signed_workspace["evidence"]),
        )
        == EXIT_OK
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["node_id"] == NODE
    assert payload["last_sequence"] == 3
    assert payload["journal_present"] is False
    # The private key is loaded to build the signer; it must not come back out.
    assert "private_key" not in payload
    assert "-----BEGIN" not in json.dumps(payload)


def test_recover_state_refuses_to_run_without_confirmation(signed_workspace):
    before = signed_workspace["state"].read_bytes()

    assert (
        run(
            "recover-state",
            *signer_args(signed_workspace),
            "--evidence",
            str(signed_workspace["evidence"]),
        )
        == EXIT_USAGE
    )

    assert signed_workspace["state"].read_bytes() == before, "state must be untouched"


def test_recover_state_rebuilds_lost_state_from_the_evidence_log(signed_workspace, capsys):
    """The disaster case: the log survived, the state file did not."""
    signed_workspace["state"].unlink()

    assert (
        run(
            "--json",
            "recover-state",
            *signer_args(signed_workspace),
            "--evidence",
            str(signed_workspace["evidence"]),
            "--confirm",
        )
        == EXIT_OK
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["state"]["last_sequence"] == 3

    # And the chain continues from there rather than restarting at 1.
    extra = signed_workspace["dir"] / "more.jsonl"
    extra.write_text(json.dumps({"source": "s", "event_type": "e"}) + "\n", encoding="utf-8")
    assert (
        run(
            "sign-log",
            *signer_args(signed_workspace),
            "--input",
            str(extra),
            "--output",
            str(signed_workspace["evidence"]),
        )
        == EXIT_OK
    )
    records = [
        json.loads(line)
        for line in signed_workspace["evidence"].read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert [r["sequence"] for r in records] == [1, 2, 3, 4]


def test_recover_state_never_rewinds_past_what_the_log_proves(signed_workspace):
    """State ahead of the log means records were lost; that must not be papered over."""
    signed_workspace["evidence"].write_text("", encoding="utf-8")

    assert (
        run(
            "recover-state",
            *signer_args(signed_workspace),
            "--evidence",
            str(signed_workspace["evidence"]),
            "--confirm",
        )
        != EXIT_OK
    )


def test_recover_state_output_contains_no_key_material(signed_workspace, capsys):
    signed_workspace["state"].unlink()
    run(
        "recover-state",
        *signer_args(signed_workspace),
        "--evidence",
        str(signed_workspace["evidence"]),
        "--confirm",
    )

    captured = capsys.readouterr()
    secret = signed_workspace["private"].read_bytes()
    assert base64.b64encode(secret).decode() not in captured.out
    assert "-----BEGIN" not in captured.out
