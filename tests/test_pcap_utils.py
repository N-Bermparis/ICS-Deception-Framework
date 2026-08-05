"""Tests for capture path validation and target parsing."""

from __future__ import annotations

import pytest

from ics_deception.datasets.pcap_utils import (
    PcapNotFoundError,
    PcapTraversalError,
    UnsupportedCaptureError,
    parse_host_port,
    validate_pcap_path,
)

# -- path validation --------------------------------------------------------


def test_accepts_a_capture_inside_the_approved_directory(approved_pcap_dir):
    resolved = validate_pcap_path("sample.pcap", approved_pcap_dir)

    assert resolved == (approved_pcap_dir / "sample.pcap").resolve()


def test_accepts_an_absolute_path_inside_the_approved_directory(approved_pcap_dir):
    absolute = approved_pcap_dir / "sample.pcap"

    assert validate_pcap_path(absolute, approved_pcap_dir) == absolute.resolve()


def test_accepts_pcapng(approved_pcap_dir):
    (approved_pcap_dir / "capture.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a")

    resolved = validate_pcap_path("capture.pcapng", approved_pcap_dir)

    assert resolved.suffix == ".pcapng"


@pytest.mark.parametrize(
    "traversal",
    [
        "../outside.pcap",
        "../../etc/passwd.pcap",
        "subdir/../../escape.pcap",
        "./../../../../../../tmp/evil.pcap",
    ],
)
def test_rejects_path_traversal(approved_pcap_dir, traversal):
    with pytest.raises(PcapTraversalError):
        validate_pcap_path(traversal, approved_pcap_dir)


def test_rejects_an_absolute_path_outside_the_approved_directory(approved_pcap_dir, tmp_path):
    outside = tmp_path / "elsewhere.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1")

    with pytest.raises(PcapTraversalError):
        validate_pcap_path(outside, approved_pcap_dir)


def test_rejects_a_symlink_escaping_the_approved_directory(approved_pcap_dir, tmp_path):
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"\xd4\xc3\xb2\xa1")
    link = approved_pcap_dir / "link.pcap"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted in this environment")

    # The path is resolved before containment is tested, so the escape is caught.
    with pytest.raises(PcapTraversalError):
        validate_pcap_path("link.pcap", approved_pcap_dir)


@pytest.mark.parametrize(
    "name",
    ["capture.txt", "capture.pcap.gz", "capture", "capture.json", "notes.md"],
)
def test_rejects_unsupported_capture_extensions(approved_pcap_dir, name):
    with pytest.raises(UnsupportedCaptureError):
        validate_pcap_path(name, approved_pcap_dir)


def test_extension_is_checked_case_insensitively(approved_pcap_dir):
    (approved_pcap_dir / "upper.PCAP").write_bytes(b"\xd4\xc3\xb2\xa1")

    assert validate_pcap_path("upper.PCAP", approved_pcap_dir).is_file()


def test_rejects_a_missing_capture(approved_pcap_dir):
    with pytest.raises(PcapNotFoundError):
        validate_pcap_path("absent.pcap", approved_pcap_dir)


def test_rejects_a_directory_named_like_a_capture(approved_pcap_dir):
    (approved_pcap_dir / "directory.pcap").mkdir()

    with pytest.raises(PcapNotFoundError):
        validate_pcap_path("directory.pcap", approved_pcap_dir)


# -- HOST:PORT parsing ------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [
        ("127.0.0.1:5020", 502, ("127.0.0.1", 5020)),
        ("127.0.0.1", 502, ("127.0.0.1", 502)),
        ("plc.lab.internal:20000", 502, ("plc.lab.internal", 20000)),
        ("plc.lab.internal", 20000, ("plc.lab.internal", 20000)),
        ("[::1]:5020", 502, ("::1", 5020)),
        ("[::1]", 502, ("::1", 502)),
        ("fe80::1", 502, ("fe80::1", 502)),
        ("  127.0.0.1:1  ", 502, ("127.0.0.1", 1)),
        ("127.0.0.1:65535", 502, ("127.0.0.1", 65535)),
    ],
)
def test_parse_host_port(value, default, expected):
    assert parse_host_port(value, default) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "host:",
        "host:abc",
        "host:0",
        "host:65536",
        "host:-1",
        ":5020",
        "[::1",
        "[::1]garbage",
    ],
)
def test_parse_host_port_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        parse_host_port(value, 502)
