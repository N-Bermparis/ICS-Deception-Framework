"""Native OpenSSL backend for ML-DSA and ML-KEM.

This is the **preferred** backend: OpenSSL's ``libcrypto`` is the implementation
most likely to be audited, optimised and constant-time on the deployment
platform. Support arrived in **OpenSSL 3.5**; anything older simply does not
expose ML-DSA, which this module detects rather than assumes.

Why the ``openssl`` executable rather than ``ctypes`` into ``libcrypto``: the
ML-DSA/ML-KEM ``EVP`` surface is new and still shifting between releases, and
binding it through ``ctypes`` would hard-code struct and symbol details that
differ across builds. Driving the CLI keeps the coupling at the level of a
documented, stable interface, and key material stays in files with restrictive
permissions rather than being marshalled through Python buffers.

Key format
----------
Public keys are exchanged as **raw** algorithm-level bytes (1952 bytes for
ML-DSA-65), not PEM/DER. Raw bytes are what the pure-Python FIPS 204 backend
consumes, and this module converts to and from ``SubjectPublicKeyInfo`` DER on
the way in and out, so the two backends interoperate byte for byte. That
conversion is verified by the test suite in both directions.

Set ``ICS_PQC_OPENSSL`` to point at a specific ``openssl`` executable when the
system one is too old (for example a locally built 3.5).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import DEFAULT_SIGNATURE_ALGORITHM
from ics_deception.pqc_evidence.crypto_backend import (
    BackendError,
    BackendUnavailableError,
    Capabilities,
    CryptoBackend,
    KeyPair,
)

__all__ = ["ENV_OPENSSL", "OpenSslBackend", "raw_public_key_from_der", "der_from_raw_public_key"]

#: Environment variable naming the ``openssl`` executable to use.
ENV_OPENSSL = "ICS_PQC_OPENSSL"

#: OpenSSL releases before this do not implement ML-DSA at all.
MIN_OPENSSL_VERSION = (3, 5, 0)

#: Timeout for any single openssl invocation, in seconds.
OPENSSL_TIMEOUT = 60.0

#: Raw public-key sizes (FIPS 204 / FIPS 203), used to strip the SPKI header.
RAW_PUBLIC_KEY_SIZES = {
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
    "ML-KEM-512": 800,
    "ML-KEM-768": 1184,
    "ML-KEM-1024": 1568,
}


def raw_public_key_from_der(der: bytes, algorithm: str) -> bytes:
    """Extract raw public-key bytes from a ``SubjectPublicKeyInfo`` DER blob.

    The SPKI wrapper is a fixed-length prefix for these algorithms (22 bytes for
    ML-DSA-65), so the raw key is simply the tail. The length is validated
    rather than trusted.
    """
    size = RAW_PUBLIC_KEY_SIZES.get(algorithm)
    if size is None:
        raise BackendError(
            f"unknown raw public key size for {algorithm}",
            code="unsupported_algorithm",
            backend="openssl",
        )
    if len(der) < size:
        raise BackendError(
            f"DER public key is {len(der)} bytes, shorter than the {size}-byte "
            f"raw {algorithm} key it should contain",
            code="invalid_public_key",
            backend="openssl",
        )
    return der[-size:]


def der_from_raw_public_key(raw: bytes, algorithm: str) -> bytes:
    """Wrap raw public-key bytes in ``SubjectPublicKeyInfo`` DER.

    The header is built explicitly rather than copied from a sample key, so the
    function works without an existing key to borrow a prefix from.
    """
    size = RAW_PUBLIC_KEY_SIZES.get(algorithm)
    if size is None:
        raise BackendError(
            f"unknown raw public key size for {algorithm}",
            code="unsupported_algorithm",
            backend="openssl",
        )
    if len(raw) != size:
        raise BackendError(
            f"raw {algorithm} public key must be {size} bytes, got {len(raw)}",
            code="invalid_public_key",
            backend="openssl",
        )

    oid = _ALGORITHM_OIDS.get(algorithm)
    if oid is None:  # pragma: no cover - guarded by the size lookup above
        raise BackendError(
            f"no OID known for {algorithm}", code="unsupported_algorithm", backend="openssl"
        )

    algorithm_identifier = _der_sequence(_der_object_identifier(oid))
    public_key_bitstring = _der_bit_string(raw)
    return _der_sequence(algorithm_identifier + public_key_bitstring)


#: NIST algorithm OIDs (2.16.840.1.101.3.4.3.x for ML-DSA, .4.4.x for ML-KEM).
_ALGORITHM_OIDS = {
    "ML-DSA-44": (2, 16, 840, 1, 101, 3, 4, 3, 17),
    "ML-DSA-65": (2, 16, 840, 1, 101, 3, 4, 3, 18),
    "ML-DSA-87": (2, 16, 840, 1, 101, 3, 4, 3, 19),
    "ML-KEM-512": (2, 16, 840, 1, 101, 3, 4, 4, 1),
    "ML-KEM-768": (2, 16, 840, 1, 101, 3, 4, 4, 2),
    "ML-KEM-1024": (2, 16, 840, 1, 101, 3, 4, 4, 3),
}


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_sequence(content: bytes) -> bytes:
    return b"\x30" + _der_length(len(content)) + content


def _der_bit_string(content: bytes) -> bytes:
    # A leading zero byte records that there are no unused trailing bits.
    body = b"\x00" + content
    return b"\x03" + _der_length(len(body)) + body


def _der_object_identifier(oid: tuple[int, ...]) -> bytes:
    first = oid[0] * 40 + oid[1]
    body = bytearray([first])
    for component in oid[2:]:
        if component < 0x80:
            body.append(component)
            continue
        chunks = []
        value = component
        while value:
            chunks.append(value & 0x7F)
            value >>= 7
        chunks.reverse()
        for index, chunk in enumerate(chunks):
            body.append(chunk | (0x80 if index < len(chunks) - 1 else 0x00))
    return b"\x06" + _der_length(len(body)) + bytes(body)


class OpenSslBackend(CryptoBackend):
    """ML-DSA and ML-KEM through the OpenSSL command-line interface."""

    name = "openssl"

    def __init__(self, executable: str | None = None) -> None:
        self._explicit = executable
        self._cached: Capabilities | None = None

    # -- discovery ---------------------------------------------------------

    def executable(self) -> str | None:
        """Return the ``openssl`` executable to use, or ``None`` if absent."""
        candidate = self._explicit or os.environ.get(ENV_OPENSSL)
        if candidate:
            return candidate if (Path(candidate).is_file() or shutil.which(candidate)) else None
        return shutil.which("openssl")

    def _run(self, args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess:
        executable = self.executable()
        if executable is None:
            raise BackendUnavailableError("no openssl executable found", backend=self.name)
        env = dict(os.environ)
        # A locally built OpenSSL needs its own shared libraries ahead of the
        # system ones, otherwise it loads the older libcrypto and fails.
        if self._explicit or os.environ.get(ENV_OPENSSL):
            lib_dir = Path(executable).resolve().parent.parent / "lib"
            if lib_dir.is_dir():
                existing = env.get("LD_LIBRARY_PATH", "")
                env["LD_LIBRARY_PATH"] = f"{lib_dir}{os.pathsep}{existing}" if existing else str(lib_dir)
        try:
            return subprocess.run(  # noqa: S603 - fixed argv, never a shell
                [executable, *args],
                input=stdin,
                capture_output=True,
                timeout=OPENSSL_TIMEOUT,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BackendError(
                f"openssl timed out after {OPENSSL_TIMEOUT}s", code="timeout", backend=self.name
            ) from exc
        except OSError as exc:
            raise BackendUnavailableError(
                f"cannot execute openssl: {exc}", backend=self.name
            ) from exc

    def capabilities(self) -> Capabilities:
        """Probe the OpenSSL version and its advertised algorithms."""
        if self._cached is not None:
            return self._cached
        self._cached = self._probe()
        return self._cached

    def _probe(self) -> Capabilities:
        executable = self.executable()
        if executable is None:
            return Capabilities(
                name=self.name,
                available=False,
                reason=(
                    "no openssl executable on PATH; install OpenSSL 3.5+ or set "
                    f"{ENV_OPENSSL} to a newer build"
                ),
            )
        try:
            result = self._run(["version"])
        except BackendError as exc:
            return Capabilities(name=self.name, available=False, reason=exc.detail)
        if result.returncode != 0:
            return Capabilities(
                name=self.name,
                available=False,
                reason=f"openssl version failed: {result.stderr.decode(errors='replace').strip()}",
            )

        version_text = result.stdout.decode(errors="replace").strip()
        parsed = _parse_openssl_version(version_text)
        if parsed is None:
            return Capabilities(
                name=self.name,
                available=False,
                version=version_text,
                reason=f"cannot parse OpenSSL version from {version_text!r}",
            )
        if parsed < MIN_OPENSSL_VERSION:
            wanted = ".".join(str(part) for part in MIN_OPENSSL_VERSION)
            return Capabilities(
                name=self.name,
                available=False,
                version=version_text,
                reason=(
                    f"OpenSSL {'.'.join(str(p) for p in parsed)} does not implement ML-DSA; "
                    f"{wanted} or newer is required. Set {ENV_OPENSSL} to a newer build, "
                    "or use the portable 'pyfips' backend."
                ),
            )

        signatures = self._list_algorithms("-signature-algorithms", "ML-DSA")
        kems = self._list_algorithms("-kem-algorithms", "ML-KEM")
        if not signatures:
            return Capabilities(
                name=self.name,
                available=False,
                version=version_text,
                reason=(
                    f"OpenSSL {version_text} reports no ML-DSA algorithms; "
                    "the active provider may not expose them"
                ),
            )
        return Capabilities(
            name=self.name,
            available=True,
            signature_algorithms=signatures,
            kem_algorithms=kems,
            provider="OpenSSL libcrypto (default provider)",
            version=version_text,
            real_pqc=True,
            details={"executable": executable, "constant_time": True},
        )

    def _list_algorithms(self, flag: str, prefix: str) -> tuple[str, ...]:
        result = self._run(["list", flag])
        if result.returncode != 0:
            return ()
        found: set[str] = set()
        for line in result.stdout.decode(errors="replace").splitlines():
            for token in line.replace("{", " ").replace("}", " ").replace(",", " ").split():
                candidate = token.strip()
                if candidate.upper().startswith(prefix) and candidate in RAW_PUBLIC_KEY_SIZES:
                    found.add(candidate)
        return tuple(sorted(found))

    def _require_available(self) -> None:
        capabilities = self.capabilities()
        if not capabilities.available:
            raise BackendUnavailableError(capabilities.reason, backend=self.name)

    # -- signatures --------------------------------------------------------

    def generate_keypair(self, algorithm: str = DEFAULT_SIGNATURE_ALGORITHM) -> KeyPair:
        """Generate an ML-DSA key pair via ``openssl genpkey``."""
        self._require_available()
        with tempfile.TemporaryDirectory(prefix="ics-pqc-") as workdir:
            private_path = Path(workdir) / "private.pem"
            result = self._run(
                ["genpkey", "-algorithm", algorithm, "-out", str(private_path)]
            )
            if result.returncode != 0:
                raise BackendError(
                    f"openssl genpkey failed for {algorithm}: "
                    f"{result.stderr.decode(errors='replace').strip()}",
                    code="keygen_failed",
                    backend=self.name,
                )
            os.chmod(private_path, 0o600)
            private_bytes = private_path.read_bytes()

            public_result = self._run(
                ["pkey", "-in", str(private_path), "-pubout", "-outform", "DER"]
            )
            if public_result.returncode != 0:
                raise BackendError(
                    "openssl failed to export the public key: "
                    f"{public_result.stderr.decode(errors='replace').strip()}",
                    code="pubkey_export_failed",
                    backend=self.name,
                )
            raw_public = raw_public_key_from_der(public_result.stdout, algorithm)

        return KeyPair(
            algorithm=algorithm,
            public_bytes=raw_public,
            private_bytes=private_bytes,
            backend=self.name,
        )

    def sign(self, private_bytes: bytes, message: bytes, algorithm: str) -> bytes:
        """Sign with ``openssl pkeyutl -sign -rawin``.

        ``private_bytes`` is the PEM produced by :meth:`generate_keypair`. It is
        written to a 0600 file inside a private temporary directory that is
        removed immediately afterwards; it is never passed on a command line.
        """
        self._require_available()
        with tempfile.TemporaryDirectory(prefix="ics-pqc-") as workdir:
            private_path = Path(workdir) / "private.pem"
            message_path = Path(workdir) / "message.bin"
            signature_path = Path(workdir) / "signature.bin"

            private_path.touch(mode=0o600)
            private_path.write_bytes(private_bytes)
            message_path.write_bytes(message)

            result = self._run(
                [
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(private_path),
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-out",
                    str(signature_path),
                ]
            )
            if result.returncode != 0:
                raise BackendError(
                    f"openssl signing failed: {result.stderr.decode(errors='replace').strip()}",
                    code="sign_failed",
                    backend=self.name,
                )
            signature = signature_path.read_bytes()
            _overwrite(private_path)
        return signature

    def verify(
        self, public_bytes: bytes, message: bytes, signature: bytes, algorithm: str
    ) -> bool:
        """Verify with ``openssl pkeyutl -verify``. Invalid input returns False."""
        self._require_available()
        if not signature:
            return False
        try:
            der = der_from_raw_public_key(public_bytes, algorithm)
        except BackendError:
            return False
        with tempfile.TemporaryDirectory(prefix="ics-pqc-") as workdir:
            public_path = Path(workdir) / "public.der"
            message_path = Path(workdir) / "message.bin"
            signature_path = Path(workdir) / "signature.bin"
            public_path.write_bytes(der)
            message_path.write_bytes(message)
            signature_path.write_bytes(signature)

            result = self._run(
                [
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_path),
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-sigfile",
                    str(signature_path),
                ]
            )
        return result.returncode == 0

    # -- key encapsulation -------------------------------------------------

    def kem_generate_keypair(self, algorithm: str = "ML-KEM-768") -> KeyPair:
        """Generate an ML-KEM key pair via ``openssl genpkey``."""
        self._require_available()
        capabilities = self.capabilities()
        if algorithm not in capabilities.kem_algorithms:
            raise BackendUnavailableError(
                f"this OpenSSL build does not expose {algorithm}", backend=self.name
            )
        with tempfile.TemporaryDirectory(prefix="ics-pqc-") as workdir:
            private_path = Path(workdir) / "kem.pem"
            result = self._run(["genpkey", "-algorithm", algorithm, "-out", str(private_path)])
            if result.returncode != 0:
                raise BackendError(
                    f"openssl genpkey failed for {algorithm}: "
                    f"{result.stderr.decode(errors='replace').strip()}",
                    code="keygen_failed",
                    backend=self.name,
                )
            os.chmod(private_path, 0o600)
            private_bytes = private_path.read_bytes()
            public_result = self._run(
                ["pkey", "-in", str(private_path), "-pubout", "-outform", "DER"]
            )
            if public_result.returncode != 0:
                raise BackendError(
                    "openssl failed to export the KEM public key",
                    code="pubkey_export_failed",
                    backend=self.name,
                )
            raw_public = raw_public_key_from_der(public_result.stdout, algorithm)
        return KeyPair(
            algorithm=algorithm,
            public_bytes=raw_public,
            private_bytes=private_bytes,
            backend=self.name,
        )

    def kem_encapsulate(
        self, public_bytes: bytes, algorithm: str = "ML-KEM-768"
    ) -> tuple[bytes, bytes]:
        """Encapsulate with ``openssl pkeyutl -encap``."""
        self._require_available()
        der = der_from_raw_public_key(public_bytes, algorithm)
        with tempfile.TemporaryDirectory(prefix="ics-pqc-") as workdir:
            public_path = Path(workdir) / "public.der"
            secret_path = Path(workdir) / "secret.bin"
            ciphertext_path = Path(workdir) / "ciphertext.bin"
            public_path.write_bytes(der)
            result = self._run(
                [
                    "pkeyutl",
                    "-encap",
                    "-pubin",
                    "-inkey",
                    str(public_path),
                    "-keyform",
                    "DER",
                    "-secret",
                    str(secret_path),
                    "-out",
                    str(ciphertext_path),
                ]
            )
            if result.returncode != 0:
                raise BackendError(
                    f"openssl encapsulation failed: "
                    f"{result.stderr.decode(errors='replace').strip()}",
                    code="kem_encapsulate_failed",
                    backend=self.name,
                )
            shared = secret_path.read_bytes()
            ciphertext = ciphertext_path.read_bytes()
            _overwrite(secret_path)
        return shared, ciphertext

    def kem_decapsulate(
        self, private_bytes: bytes, ciphertext: bytes, algorithm: str = "ML-KEM-768"
    ) -> bytes:
        """Decapsulate with ``openssl pkeyutl -decap``."""
        self._require_available()
        with tempfile.TemporaryDirectory(prefix="ics-pqc-") as workdir:
            private_path = Path(workdir) / "kem.pem"
            ciphertext_path = Path(workdir) / "ciphertext.bin"
            secret_path = Path(workdir) / "secret.bin"
            private_path.touch(mode=0o600)
            private_path.write_bytes(private_bytes)
            ciphertext_path.write_bytes(ciphertext)
            result = self._run(
                [
                    "pkeyutl",
                    "-decap",
                    "-inkey",
                    str(private_path),
                    "-in",
                    str(ciphertext_path),
                    "-secret",
                    str(secret_path),
                ]
            )
            if result.returncode != 0:
                raise BackendError(
                    f"openssl decapsulation failed: "
                    f"{result.stderr.decode(errors='replace').strip()}",
                    code="kem_decapsulate_failed",
                    backend=self.name,
                )
            shared = secret_path.read_bytes()
            _overwrite(secret_path)
            _overwrite(private_path)
        return shared


def _overwrite(path: Path) -> None:
    """Best-effort overwrite of a temporary file holding key material.

    Python cannot guarantee erasure on a journalling or copy-on-write
    filesystem, and CPython cannot wipe the interpreter's own byte buffers. This
    reduces the window rather than eliminating it, which is the honest claim.
    """
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:  # pragma: no cover - the directory is removed regardless
        pass


def _parse_openssl_version(text: str) -> tuple[int, ...] | None:
    """Extract ``(major, minor, patch)`` from an ``openssl version`` string."""
    parts = text.split()
    if len(parts) < 2 or parts[0] != "OpenSSL":
        return None
    raw = parts[1]
    numbers: list[int] = []
    current = ""
    for character in raw:
        if character.isdigit():
            current += character
        elif character == ".":
            if current:
                numbers.append(int(current))
                current = ""
        else:
            break
    if current:
        numbers.append(int(current))
    if not numbers:
        return None
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def openssl_report() -> dict[str, Any]:
    """Return a capability snapshot for diagnostics."""
    return OpenSslBackend().capabilities().to_dict()
