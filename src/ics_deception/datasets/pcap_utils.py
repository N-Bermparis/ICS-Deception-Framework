"""PCAP path validation and target parsing.

Kept free of Scapy so that the controller (and the unit tests) can validate a
replay request without importing a packet-manipulation library.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "ALLOWED_PCAP_SUFFIXES",
    "PcapNotFoundError",
    "PcapPathError",
    "PcapTraversalError",
    "UnsupportedCaptureError",
    "parse_host_port",
    "validate_pcap_path",
]

#: The only capture container formats accepted for replay.
ALLOWED_PCAP_SUFFIXES = frozenset({".pcap", ".pcapng"})


class PcapPathError(ValueError):
    """Base class for rejected capture paths."""


class UnsupportedCaptureError(PcapPathError):
    """The file extension is not an accepted capture format."""


class PcapTraversalError(PcapPathError):
    """The resolved path escapes the approved capture directory."""


class PcapNotFoundError(PcapPathError):
    """The capture does not exist, or is not a regular file."""


def validate_pcap_path(candidate: str | Path, approved_dir: str | Path) -> Path:
    """Validate a user-supplied capture path against an approved directory.

    The check order matters. The extension is validated first (cheap, and it
    rejects the largest class of mistakes), then the path is **fully resolved**
    — following symlinks and collapsing ``..`` — *before* containment is
    tested, then existence is checked last. Resolving before comparing is what
    makes ``../../etc/passwd`` and symlink escapes detectable.

    Returns the resolved :class:`~pathlib.Path` on success.

    Raises
    ------
    UnsupportedCaptureError
        Extension is not ``.pcap`` or ``.pcapng``.
    PcapTraversalError
        Resolved path lies outside ``approved_dir``.
    PcapNotFoundError
        Resolved path does not exist or is not a regular file.
    """
    raw = Path(candidate)
    if raw.suffix.lower() not in ALLOWED_PCAP_SUFFIXES:
        raise UnsupportedCaptureError(
            f"unsupported capture extension {raw.suffix!r}; "
            f"allowed: {sorted(ALLOWED_PCAP_SUFFIXES)}"
        )

    approved = Path(approved_dir).expanduser().resolve()
    # A relative candidate is interpreted relative to the approved directory.
    combined = raw.expanduser() if raw.is_absolute() else approved / raw
    resolved = combined.resolve()

    if resolved != approved and approved not in resolved.parents:
        raise PcapTraversalError(
            f"capture path escapes the approved directory: {resolved} not under {approved}"
        )

    if not resolved.is_file():
        raise PcapNotFoundError(f"capture not found: {resolved}")

    return resolved


def parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    """Parse a ``HOST``, ``HOST:PORT`` or ``[IPv6]:PORT`` target specification.

    Examples
    --------
    >>> parse_host_port("127.0.0.1:5020", 502)
    ('127.0.0.1', 5020)
    >>> parse_host_port("plc.lab", 502)
    ('plc.lab', 502)
    >>> parse_host_port("[::1]:20000", 20000)
    ('::1', 20000)
    """
    text = value.strip()
    if not text:
        raise ValueError("empty host specification")

    if text.startswith("["):
        # Bracketed IPv6 literal, optionally followed by :PORT.
        close = text.find("]")
        if close == -1:
            raise ValueError(f"unterminated IPv6 literal: {value!r}")
        host = text[1:close]
        remainder = text[close + 1 :]
        if not remainder:
            port = default_port
        elif remainder.startswith(":"):
            port = _parse_port(remainder[1:], value)
        else:
            raise ValueError(f"invalid IPv6 target: {value!r}")
    elif text.count(":") > 1:
        # Bare IPv6 literal without a port, e.g. "fe80::1".
        host, port = text, default_port
    elif ":" in text:
        host, _, port_text = text.partition(":")
        port = _parse_port(port_text, value)
    else:
        host, port = text, default_port

    if not host:
        raise ValueError(f"missing host in target: {value!r}")
    return host, port


def _parse_port(text: str, original: str) -> int:
    if not text.isdigit():
        raise ValueError(f"invalid port in target: {original!r}")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range in target: {original!r}")
    return port
