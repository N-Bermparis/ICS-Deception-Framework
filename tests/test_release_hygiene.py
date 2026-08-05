"""Release hygiene: line endings, portable paths, permissions and no secrets.

These are cheap checks that catch defects which are invisible in an editor but
break a user's first five minutes — a shell script with CRLF, a ZIP full of
backslash paths, a key that slipped into the tree.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

#: Files that must use LF line endings to work on Linux.
CRLF_SENSITIVE_SUFFIXES = {".sh", ".py", ".toml", ".cff", ".yml", ".yaml", ".json", ".md"}
CRLF_SENSITIVE_NAMES = {"Makefile", ".gitignore", ".env.example"}

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "build",
    "dist",
    "runtime",
    "release",
    "keys",
    "archives",
    "node_modules",
}


def tracked_files() -> list[Path]:
    """Every source file in the working tree, excluding generated directories."""
    found: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(REPO_ROOT)
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in relative.parts):
            continue
        found.append(relative)
    return sorted(found)


# ===========================================================================
# Line endings
# ===========================================================================


def test_gitattributes_enforces_lf_in_the_repository():
    """Git normalises line endings on commit, whatever the working tree does.

    A Windows checkout may legitimately hold CRLF locally (``core.autocrlf``),
    so the guarantee that matters is what gets *committed* and what gets
    *shipped* — enforced here and by the archive test below.
    """
    attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")

    assert "* text=auto eol=lf" in attributes
    for pattern in ("*.sh", "*.py", "*.yml", "Makefile"):
        assert f"{pattern}" in attributes


def test_the_deployment_script_runs_under_bash_as_checked_out():
    """Whatever the line endings on disk, bash must be able to parse it."""
    result = subprocess.run(
        ["bash", "-n", str(REPO_ROOT / "scripts/deploy_rpi.sh")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (REPO_ROOT / "scripts/deploy_rpi.sh").read_bytes().startswith(b"#!/usr/bin/env bash")


# ===========================================================================
# Permissions and secrets
# ===========================================================================


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_the_deployment_script_is_executable():
    mode = (REPO_ROOT / "scripts/deploy_rpi.sh").stat().st_mode

    assert mode & stat.S_IXUSR


def test_no_private_key_material_is_present():
    offenders = []
    for relative in tracked_files():
        if relative.suffix in {".key", ".pem", ".pqcarch"} or relative.name.startswith("id_rsa"):
            offenders.append(relative.as_posix())
            continue
        data = (REPO_ROOT / relative).read_bytes()[:400]
        if b"-----BEGIN" in data and b"PRIVATE KEY" in data:
            offenders.append(relative.as_posix())

    assert offenders == [], f"key material in the tree: {offenders}"


def test_no_runtime_artifacts_are_present():
    offenders = [
        relative.as_posix()
        for relative in tracked_files()
        if relative.suffix in {".jsonl", ".log", ".pcap", ".pcapng", ".cap", ".pyc", ".so", ".o"}
    ]

    assert offenders == [], f"runtime artifacts in the tree: {offenders}"


# ===========================================================================
# Release ZIP
# ===========================================================================


@pytest.mark.skipif(sys.platform.startswith("win"), reason="release build is exercised on POSIX")
def test_the_release_zip_is_portable_and_clean(tmp_path):
    """Build a real release and inspect it, rather than trusting the builder."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/make_release.py"), "--output", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, f"release build failed:\n{result.stdout}\n{result.stderr}"

    archives = list(tmp_path.glob("*.zip"))
    assert len(archives) == 1, f"expected one archive, got {archives}"

    with zipfile.ZipFile(archives[0]) as bundle:
        names = bundle.namelist()
        assert names, "the archive is empty"

        assert not [n for n in names if "\\" in n], "ZIP entries must use forward slashes"
        assert not [n for n in names if n.startswith("/") or ".." in n.split("/")]
        assert not [
            n
            for n in names
            if n.endswith((".pyc", ".key", ".pem", ".pqcarch", ".jsonl", ".log", ".pcap"))
        ], "artifacts leaked into the archive"
        assert not [
            n
            for n in names
            if any(
                part in SKIP_DIRS or part.endswith(".egg-info") for part in n.split("/")
            )
        ], "generated directories leaked into the archive"

        script = [i for i in bundle.infolist() if i.filename.endswith("scripts/deploy_rpi.sh")]
        assert script, "the deployment script is missing from the release"
        mode = (script[0].external_attr >> 16) & 0o777
        assert mode & 0o111, f"deploy_rpi.sh lost its executable bit (mode {mode:04o})"

        # And the shipped copy must still be LF.
        assert b"\r\n" not in bundle.read(script[0].filename)

    assert (tmp_path / "SHA256SUMS").is_file()


@pytest.mark.skipif(sys.platform.startswith("win"), reason="release build is exercised on POSIX")
def test_the_release_build_is_deterministic(tmp_path):
    """The same tree must produce a byte-identical archive."""
    import hashlib

    digests = []
    for run in ("first", "second"):
        target = tmp_path / run
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/make_release.py"), "--output", str(target)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, result.stderr
        archive = next(target.glob("*.zip"))
        digests.append(hashlib.sha256(archive.read_bytes()).hexdigest())

    assert digests[0] == digests[1], "the release build is not reproducible"


def test_the_version_is_consistent_across_metadata():
    import re

    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE).group(1)

    package = (REPO_ROOT / "src/ics_deception/__init__.py").read_text(encoding="utf-8")
    citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")

    assert f'__version__ = "{version}"' in package
    assert f"version: {version}" in citation

    from ics_deception import __version__

    assert __version__ == version
