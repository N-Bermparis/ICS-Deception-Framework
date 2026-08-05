"""Deployment script: syntax, argument handling, dry run and the systemd unit.

Nothing here contacts a network. Every test drives ``--dry-run`` or argument
validation, so the suite can assert on exactly what *would* be deployed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from tests.conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "deploy_rpi.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or sys.platform.startswith("win"),
    reason="the deployment script requires a POSIX bash",
)


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=60, check=False
    )


@pytest.fixture(scope="module")
def dry_run() -> subprocess.CompletedProcess:
    result = run("--host", "10.0.0.9", "--user", "pi", "--modbus-host", "10.0.0.5", "--dry-run")
    assert result.returncode == 0, result.stderr
    return result


# -- syntax -----------------------------------------------------------------


def test_the_script_passes_bash_syntax_checking():
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=60, check=False
    )

    assert result.returncode == 0, result.stderr


def test_the_embedded_remote_script_is_also_valid_bash(dry_run, tmp_path):
    """The remote block is a quoted heredoc, so `bash -n` on the outer file
    does not check it. Extract and check it separately."""
    output = dry_run.stdout
    marker = "==> Remote script that would run:"
    assert marker in output
    remote = output.split(marker, 1)[1]
    remote_path = tmp_path / "remote.sh"
    remote_path.write_text(remote, encoding="utf-8")

    result = subprocess.run(
        ["bash", "-n", str(remote_path)], capture_output=True, text=True, timeout=60, check=False
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_shellcheck_is_clean():
    result = subprocess.run(
        ["shellcheck", str(SCRIPT)], capture_output=True, text=True, timeout=120, check=False
    )

    assert result.returncode == 0, result.stdout


def test_the_script_is_marked_executable():
    """The repository tracks the executable bit; it is also documented that
    `bash scripts/deploy_rpi.sh` works if the bit is lost in transit."""
    import os
    import stat

    mode = SCRIPT.stat().st_mode
    if os.name == "nt":
        pytest.skip("no POSIX permission bits on this filesystem")
    assert mode & stat.S_IXUSR, "scripts/deploy_rpi.sh should carry the executable bit"


def test_the_help_documents_both_invocation_styles():
    result = run("--help")

    assert result.returncode == 0
    assert "bash scripts/deploy_rpi.sh" in result.stdout
    assert "--dry-run" in result.stdout


# -- argument validation ----------------------------------------------------


def test_the_host_is_required():
    result = run()

    assert result.returncode == 2
    assert "--host is required" in result.stderr


def test_an_unknown_option_is_rejected():
    result = run("--host", "h", "--bogus")

    assert result.returncode == 2
    assert "unknown option" in result.stderr


@pytest.mark.parametrize("port", ["0", "-1", "70000", "abc", ""])
def test_invalid_ports_are_rejected(port):
    result = run("--host", "h", "--modbus-port", port, "--dry-run")

    assert result.returncode == 2
    assert "--modbus-port" in result.stderr


@pytest.mark.parametrize("interval", ["0", "-5", "abc"])
def test_invalid_intervals_are_rejected(interval):
    result = run("--host", "h", "--interval", interval, "--dry-run")

    assert result.returncode == 2
    assert "--interval" in result.stderr


def test_a_relative_destination_is_rejected():
    result = run("--host", "h", "--dest", "relative/path", "--dry-run")

    assert result.returncode == 2
    assert "absolute path" in result.stderr


def test_an_empty_service_name_is_rejected():
    result = run("--host", "h", "--service-name", "", "--dry-run")

    assert result.returncode == 2


# -- dry run ----------------------------------------------------------------


def test_dry_run_contacts_nothing_and_reports_the_plan(dry_run):
    assert "DRY RUN" in dry_run.stdout
    assert "nothing will be copied" in dry_run.stdout
    assert "pi@10.0.0.9" in dry_run.stdout
    assert "10.0.0.5:5020" in dry_run.stdout


def test_dry_run_uses_the_documented_default_destination():
    result = run("--host", "10.0.0.9", "--dry-run")

    assert "/home/pi/ics-deception" in result.stdout


def test_dry_run_honours_a_custom_destination():
    result = run("--host", "10.0.0.9", "--dest", "/srv/deception", "--dry-run")

    assert "/srv/deception" in result.stdout


# -- exclusions -------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        ".git/",
        ".venv/",
        "__pycache__/",
        ".pytest_cache/",
        ".ruff_cache/",
        "build/",
        "runtime/",
        "*.log",
        "*.jsonl",
        "*.pcap",
        "*.pcapng",
        ".env",
        "keys/",
        "*.pem",
        "*.key",
        "id_rsa*",
        "*.pqcarch",
        "config/controller.json",
    ],
)
def test_sensitive_paths_are_excluded_from_the_sync(dry_run, pattern):
    assert f"- {pattern}" in dry_run.stdout, f"{pattern} must never be copied to a node"


def test_private_keys_and_archives_are_excluded(dry_run):
    excluded = dry_run.stdout
    for secret in ("*.pem", "*.key", "keys/", "*.pqcarch"):
        assert secret in excluded


# -- systemd unit -----------------------------------------------------------


def test_the_unit_is_installed_at_user_level(dry_run):
    assert ".config/systemd/user" in dry_run.stdout
    assert "systemctl --user daemon-reload" in dry_run.stdout


def test_the_unit_refuses_to_run_as_root(dry_run):
    assert 'if [ "$(id -u)" -eq 0 ]' in dry_run.stdout
    assert "refusing to deploy as root" in dry_run.stdout


@pytest.mark.parametrize(
    "directive",
    [
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=full",
        "ProtectHome=read-only",
        "RestrictSUIDSGID=true",
        "MemoryDenyWriteExecute=true",
        "LockPersonality=true",
        "Restart=on-failure",
        "WantedBy=default.target",
    ],
)
def test_the_unit_carries_its_hardening_directives(dry_run, directive):
    assert directive in dry_run.stdout


def test_the_unit_runs_the_fake_plc_with_its_target(dry_run):
    assert "ics-fake-plc" in dry_run.stdout
    assert "--target-host ${MODBUS_HOST}" in dry_run.stdout
    assert "--target-port ${MODBUS_PORT}" in dry_run.stdout


def test_the_controller_is_never_installed_or_started(dry_run):
    assert "controller was deliberately not installed" in dry_run.stdout
    assert "ics-controller" not in dry_run.stdout


def test_no_signing_key_is_created_during_deployment(dry_run):
    assert "never generates a signing key" in dry_run.stdout
    assert "generate-key" in dry_run.stdout  # points the operator at the right step


def test_evidence_sealing_is_disabled_by_default(dry_run):
    assert "pqc evidence mode   = disabled" in dry_run.stdout


def test_enabling_evidence_sealing_requires_a_provisioned_key():
    result = run("--host", "10.0.0.9", "--pqc-mode", "sign", "--dry-run")

    assert result.returncode == 2
    assert "--pqc-private-key" in result.stderr
    assert "never generates a signing key" in result.stderr


@pytest.mark.parametrize("mode", ["bogus", "SIGN", "enabled", ""])
def test_an_invalid_evidence_mode_is_rejected(mode):
    result = run("--host", "10.0.0.9", "--pqc-mode", mode, "--dry-run")

    assert result.returncode == 2
    assert "--pqc-mode must be" in result.stderr


def test_a_missing_private_key_is_rejected(tmp_path):
    result = run(
        "--host",
        "10.0.0.9",
        "--pqc-mode",
        "sign",
        "--pqc-node-id",
        "n",
        "--pqc-key-id",
        "k",
        "--pqc-private-key",
        str(tmp_path / "absent.key"),
        "--dry-run",
    )

    assert result.returncode == 2
    assert "private key not found" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_a_group_readable_private_key_is_rejected(tmp_path):
    """A key others can read must be replaced, not deployed."""
    key = tmp_path / "node.key"
    key.write_text("not a real key", encoding="utf-8")
    key.chmod(0o644)

    result = run(
        "--host",
        "10.0.0.9",
        "--pqc-mode",
        "sign",
        "--pqc-node-id",
        "n",
        "--pqc-key-id",
        "k",
        "--pqc-private-key",
        str(key),
        "--dry-run",
    )

    assert result.returncode == 2
    assert "must be 600 or 400" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_the_private_key_contents_are_never_printed(tmp_path):
    key = tmp_path / "node.key"
    key.write_text("SUPER-SECRET-KEY-MATERIAL", encoding="utf-8")
    key.chmod(0o600)

    result = run(
        "--host",
        "10.0.0.9",
        "--pqc-mode",
        "dual",
        "--pqc-node-id",
        "rpi-01",
        "--pqc-key-id",
        "rpi-01-k1",
        "--pqc-private-key",
        str(key),
        "--dry-run",
    )

    assert result.returncode == 0
    assert "SUPER-SECRET-KEY-MATERIAL" not in result.stdout
    assert "SUPER-SECRET-KEY-MATERIAL" not in result.stderr
    assert "pqc evidence mode   = dual" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_the_unit_carries_the_evidence_environment(tmp_path):
    key = tmp_path / "node.key"
    key.write_text("key", encoding="utf-8")
    key.chmod(0o600)

    result = run(
        "--host",
        "10.0.0.9",
        "--pqc-mode",
        "dual",
        "--pqc-node-id",
        "rpi-01",
        "--pqc-key-id",
        "rpi-01-k1",
        "--pqc-private-key",
        str(key),
        "--dry-run",
    )

    for variable in (
        "ICS_PQC_EVIDENCE_MODE",
        "ICS_PQC_NODE_ID",
        "ICS_PQC_KEY_ID",
        "ICS_PQC_PRIVATE_KEY",
        "ICS_PQC_EVIDENCE_LOG",
        "ICS_PQC_STATE",
        "ICS_PQC_PRODUCTION=1",
    ):
        assert variable in result.stdout


def test_runtime_directories_are_created_owner_only(dry_run):
    assert 'chmod 0700 "${DEST_DIR}/runtime"' in dry_run.stdout
    assert 'chmod 0700 "${DEST_DIR}/runtime/pqc"' in dry_run.stdout


def test_the_deployment_prints_a_summary(dry_run):
    assert "Deployment summary" in dry_run.stdout
    assert "evidence mode" in dry_run.stdout


def test_nothing_is_started_unless_start_is_passed(dry_run):
    assert "start after install = no" in dry_run.stdout
    assert "Unit installed but NOT started" in dry_run.stdout


def test_start_is_reflected_in_the_plan():
    result = run("--host", "10.0.0.9", "--start", "--dry-run")

    assert "start after install = yes" in result.stdout


def test_the_package_is_installed_from_pyproject(dry_run):
    assert "python -m pip install ." in dry_run.stdout
    # The old script installed from a requirements.txt reached by a broken
    # relative path; nothing may install from one now.
    assert "pip install -r" not in dry_run.stdout


def test_the_native_components_are_built_when_a_compiler_exists(dry_run):
    assert "make -C src/native" in dry_run.stdout
