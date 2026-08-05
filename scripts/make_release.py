#!/usr/bin/env python3
"""Build a clean, portable release directory and ZIP.

Why a script rather than ``zip -r`` or ``Compress-Archive``:

* **Portable paths.** ZIP entries must use ``/`` separators. Windows archivers
  happily write ``src\\module\\file.py``, which then extracts as a single
  oddly-named file on Linux. This writes entries explicitly.
* **Executable bits.** ZIP stores POSIX permissions in the high bits of
  ``external_attr``. Most tooling drops them, so ``scripts/deploy_rpi.sh``
  arrives without its executable bit. This sets it deliberately.
* **Hygiene by construction.** Rather than deleting artifacts after the fact,
  the file list is built from an allowlist of tracked source paths, and then
  *verified* against a denylist. A key, capture, log or cache cannot reach the
  archive even if one is sitting in the working tree.
* **Reproducibility.** Entries are sorted and given a fixed timestamp, so the
  same tree produces a byte-identical ZIP.

Usage::

    python scripts/make_release.py --output dist/release
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import stat
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Fixed ZIP timestamp (1980-01-01), so archives are reproducible.
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

#: Files and directories that belong in a release.
INCLUDE = (
    ".env.example",
    ".gitattributes",
    ".github",
    ".gitignore",
    "BUG_FIX_SUMMARY.md",
    "CHANGELOG.md",
    "CITATION.cff",
    "CONTRIBUTING.md",
    "GITHUB_UPLOAD_CHECKLIST.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "RELEASE_NOTES.md",
    "SECURITY.md",
    "VALIDATION_REPORT.md",
    "config",
    "data",
    "docs",
    "pyproject.toml",
    "scripts",
    "src",
    "tests",
)

#: Directory names that must never appear anywhere in the archive.
FORBIDDEN_DIRS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "archives",
        "benchmarks",
        "build",
        "dist",
        "keys",
        "node_modules",
        "runtime",
        "venv",
    }
)

#: File suffixes that must never appear in the archive.
FORBIDDEN_SUFFIXES = frozenset(
    {
        ".a",
        ".cap",
        ".jsonl",
        ".key",
        ".log",
        ".o",
        ".pcap",
        ".pcapng",
        ".pem",
        ".pqcarch",
        ".pyc",
        ".pyd",
        ".pyo",
        ".so",
    }
)

#: Exact file names that must never appear in the archive.
FORBIDDEN_NAMES = frozenset(
    {
        ".env",
        "config/controller.json",
        "id_rsa",
        "plc_state.json",
        "registry.json",
    }
)

#: Paths that must carry the executable bit in the archive.
EXECUTABLE = ("scripts/deploy_rpi.sh", "scripts/make_release.py")

#: Suffixes whose files must use LF line endings. A shell script shipped
#: with CRLF fails on Linux with a confusing carriage-return error, so text
#: files are normalised as they enter the archive.
CRLF_SENSITIVE = frozenset({".sh", ".py", ".toml", ".cff", ".yml", ".yaml", ".json", ".md"})
CRLF_SENSITIVE_NAMES = frozenset({"Makefile", ".gitignore", ".env.example"})


def project_version() -> str:
    """Read the version from pyproject.toml without importing the package."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "0.0.0"


def is_forbidden_dir(part: str) -> bool:
    """Whether a single path component names a directory that must be excluded.

    Suffix matching matters here: build metadata lands in directories like
    ``ics_deception.egg-info``, whose exact name is not knowable in advance, so
    an exact-name-only check silently lets them into the archive.
    """
    return part in FORBIDDEN_DIRS or part.endswith((".egg-info", ".dist-info"))


def collect_files() -> list[Path]:
    """Return every file to ship, as paths relative to the repository root."""
    collected: list[Path] = []
    for entry in INCLUDE:
        source = REPO_ROOT / entry
        if not source.exists():
            print(f"warning: {entry} does not exist, skipping", file=sys.stderr)
            continue
        if source.is_file():
            collected.append(Path(entry))
            continue
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(REPO_ROOT)
            if any(is_forbidden_dir(part) for part in relative.parts):
                continue
            collected.append(relative)
    return sorted(set(collected))


def check_hygiene(files: list[Path]) -> list[str]:
    """Return a list of hygiene violations; empty means the set is clean."""
    problems: list[str] = []
    for relative in files:
        posix = relative.as_posix()
        if any(is_forbidden_dir(part) for part in relative.parts):
            problems.append(f"forbidden directory in {posix}")
        if relative.suffix.lower() in FORBIDDEN_SUFFIXES:
            problems.append(f"forbidden file type: {posix}")
        if posix in FORBIDDEN_NAMES or relative.name in FORBIDDEN_NAMES:
            problems.append(f"forbidden file: {posix}")
        # A stray private key would not necessarily have a telltale suffix.
        try:
            data = (REPO_ROOT / relative).read_bytes()
        except OSError:  # pragma: no cover - unreadable file
            continue
        if b"-----BEGIN" in data[:200] and b"PRIVATE KEY" in data[:200]:
            problems.append(f"file appears to contain a private key: {posix}")
    return problems


def build_directory(files: list[Path], destination: Path) -> Path:
    """Copy the release file set into a clean directory."""
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for relative in files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive_bytes(relative))
        shutil.copystat(REPO_ROOT / relative, target)
    for executable in EXECUTABLE:
        path = destination / executable
        if path.is_file():
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return destination


def needs_lf(relative: Path) -> bool:
    """Whether this file must ship with LF line endings."""
    return relative.suffix in CRLF_SENSITIVE or relative.name in CRLF_SENSITIVE_NAMES


def archive_bytes(relative: Path) -> bytes:
    """Read a file, normalising CRLF to LF for text that needs it.

    Normalising here rather than only checking means a checkout on a filesystem
    or editor that inserts CRLF still produces a correct artifact. A shell
    script shipped with CRLF fails on Linux with a confusing carriage-return
    error, so this is the last place to get it right.
    """
    data = (REPO_ROOT / relative).read_bytes()
    if needs_lf(relative):
        data = data.replace(b"\r\n", b"\n")
    return data


def build_zip(files: list[Path], zip_path: Path, prefix: str) -> Path:
    """Write the ZIP with forward-slash entries and preserved executable bits."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    executables = set(EXECUTABLE)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for relative in files:
            posix = relative.as_posix()
            # Explicit forward slashes: never let the OS separator leak in.
            info = zipfile.ZipInfo(f"{prefix}/{posix}", date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if posix in executables else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            bundle.writestr(info, archive_bytes(relative))
    return zip_path


def verify_zip(zip_path: Path) -> list[str]:
    """Re-open the finished ZIP and check it independently of how it was built."""
    problems: list[str] = []
    with zipfile.ZipFile(zip_path) as bundle:
        bad = bundle.testzip()
        if bad is not None:
            problems.append(f"corrupt entry: {bad}")
        for info in bundle.infolist():
            name = info.filename
            if needs_lf(Path(name)) and b"\r\n" in bundle.read(name):
                problems.append(f"archived file has CRLF line endings: {name}")
            if "\\" in name:
                problems.append(f"backslash in entry name: {name!r}")
            if name.startswith("/") or ".." in name.split("/"):
                problems.append(f"unsafe entry name: {name!r}")
            parts = name.split("/")
            if any(is_forbidden_dir(part) for part in parts):
                problems.append(f"forbidden directory in archive: {name}")
            if Path(name).suffix.lower() in FORBIDDEN_SUFFIXES:
                problems.append(f"forbidden file type in archive: {name}")
        for executable in EXECUTABLE:
            matches = [i for i in bundle.infolist() if i.filename.endswith(executable)]
            for info in matches:
                mode = (info.external_attr >> 16) & 0o777
                if not mode & 0o111:
                    problems.append(f"{info.filename} lost its executable bit (mode {mode:04o})")
    return problems


def write_checksums(directory: Path) -> Path:
    """Write a SHA256SUMS file covering every artifact in ``directory``."""
    checksum_path = directory / "SHA256SUMS"
    lines: list[str] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return checksum_path


def main(argv: list[str] | None = None) -> int:
    """Build the release directory, ZIP and checksums."""
    parser = argparse.ArgumentParser(description="Build a clean, portable release artifact.")
    parser.add_argument("--output", default="dist/release", help="output directory")
    parser.add_argument("--name", default="ICS-Deception-Framework", help="artifact base name")
    parser.add_argument(
        "--keep-directory",
        action="store_true",
        help="also keep the unpacked release directory next to the ZIP",
    )
    args = parser.parse_args(argv)

    version = project_version()
    prefix = f"{args.name}-v{version}"
    output = Path(args.output).expanduser().resolve()

    files = collect_files()
    print(f"collected {len(files)} file(s) for {prefix}")

    problems = check_hygiene(files)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    output.mkdir(parents=True, exist_ok=True)
    zip_path = build_zip(files, output / f"{prefix}.zip", prefix)
    print(f"wrote {zip_path} ({zip_path.stat().st_size // 1024} KiB)")

    problems = verify_zip(zip_path)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print("archive verified: forward-slash paths, executable bits preserved, no artifacts")

    if args.keep_directory:
        directory = build_directory(files, output / prefix)
        print(f"wrote {directory}/")

    checksums = write_checksums(output)
    print(f"wrote {checksums}")
    print(checksums.read_text(encoding="utf-8").strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
