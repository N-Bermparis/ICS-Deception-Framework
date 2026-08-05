"""Cryptographic backend abstraction and capability detection.

The evidence logic must not be welded to one command-line tool or one library,
because ML-DSA support is still arriving unevenly: OpenSSL gained it in 3.5,
distributions lag, and Raspberry Pi images lag further. So backends are pluggable
and selected at runtime by capability, not by assumption.

Backends shipped here
---------------------
``openssl`` (in :mod:`~ics_deception.pqc_evidence.openssl_backend`)
    Native OpenSSL ``libcrypto`` via the ``openssl`` executable. **Preferred**
    when the installed OpenSSL is 3.5 or newer and its provider exposes
    ML-DSA-65 / ML-KEM-768.
``pyfips``
    Pure-Python FIPS 204 / FIPS 203 implementations (``dilithium-py`` and
    ``kyber-py``). Real ML-DSA and real ML-KEM — *not* a mock and not a
    classical substitute — just slower and not constant-time. Portable to any
    platform with a Python interpreter, which is what makes CI able to exercise
    the genuine cryptographic path everywhere.
``insecure-test-only``
    A deterministic stand-in for unit tests. It is **not** a signature scheme
    and provides no security whatsoever. It refuses to load unless explicitly
    requested *and* production mode is off, and every key it emits is stamped
    with an unmistakable marker.

There is deliberately **no** fallback to RSA, ECDSA, Ed25519 or HMAC. If no
post-quantum backend is available the operation fails with a structured
:class:`BackendUnavailableError` explaining exactly what is missing.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from ics_deception.pqc_evidence import (
    DEFAULT_SIGNATURE_ALGORITHM,
    EvidenceError,
)

__all__ = [
    "BackendError",
    "BackendUnavailableError",
    "Capabilities",
    "CryptoBackend",
    "KeyPair",
    "PYFIPS_BACKEND",
    "TEST_BACKEND",
    "TEST_KEY_MARKER",
    "available_backends",
    "describe_capabilities",
    "detect_private_key_backend",
    "get_backend",
    "real_backends",
    "select_backend",
    "select_real_backend",
]

#: Name of the pure-Python real-PQC backend.
PYFIPS_BACKEND = "pyfips"

#: Name of the deterministic test-only backend. Named to be impossible to
#: mistake for something safe in a log, a config file or a report.
TEST_BACKEND = "insecure-test-only"

#: Prefix stamped into every key produced by the test backend.
TEST_KEY_MARKER = b"INSECURE-TEST-ONLY-KEY-DO-NOT-USE"

#: Environment variable that forces a specific backend.
ENV_BACKEND = "ICS_PQC_BACKEND"

#: Set to "1" to forbid the test backend even when explicitly requested.
ENV_PRODUCTION = "ICS_PQC_PRODUCTION"

_ML_DSA_ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
_ML_KEM_ALGORITHMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")


class BackendError(EvidenceError):
    """A cryptographic operation failed.

    Structured rather than generic: ``code`` is stable and machine-readable,
    ``detail`` carries the human explanation, and ``backend`` says who failed.
    """

    def __init__(self, message: str, code: str = "backend_error", backend: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.backend = backend
        self.detail = message

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable description of the failure."""
        return {"error": self.code, "backend": self.backend, "detail": self.detail}


class BackendUnavailableError(BackendError):
    """No backend can provide the requested algorithm."""

    def __init__(self, message: str, backend: str = "") -> None:
        super().__init__(message, code="backend_unavailable", backend=backend)


@dataclass(frozen=True)
class Capabilities:
    """What a backend can actually do, determined at runtime."""

    name: str
    available: bool
    signature_algorithms: tuple[str, ...] = ()
    kem_algorithms: tuple[str, ...] = ()
    provider: str = ""
    version: str = ""
    #: True for backends that provide genuine post-quantum cryptography.
    real_pqc: bool = True
    #: Why the backend is unavailable, when it is.
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def supports_signature(self, algorithm: str) -> bool:
        """Return whether this backend can sign with ``algorithm``."""
        return self.available and algorithm in self.signature_algorithms

    def supports_kem(self, algorithm: str) -> bool:
        """Return whether this backend can run ``algorithm`` key encapsulation."""
        return self.available and algorithm in self.kem_algorithms

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable capability record."""
        return asdict(self)


@dataclass(frozen=True)
class KeyPair:
    """A raw public/private key pair.

    ``private_bytes`` is sensitive: never log it, never serialise it into a
    report, never write it anywhere without restrictive permissions.
    """

    algorithm: str
    public_bytes: bytes
    private_bytes: bytes = field(repr=False)
    backend: str = ""

    def __repr__(self) -> str:  # pragma: no cover - defensive against leaks
        return (
            f"KeyPair(algorithm={self.algorithm!r}, backend={self.backend!r}, "
            f"public_bytes=<{len(self.public_bytes)} bytes>, private_bytes=<redacted>)"
        )


class CryptoBackend(ABC):
    """Interface every backend implements."""

    name: str = "abstract"

    @abstractmethod
    def capabilities(self) -> Capabilities:
        """Probe and return this backend's runtime capabilities."""

    @abstractmethod
    def generate_keypair(self, algorithm: str = DEFAULT_SIGNATURE_ALGORITHM) -> KeyPair:
        """Generate a signature key pair."""

    @abstractmethod
    def sign(self, private_bytes: bytes, message: bytes, algorithm: str) -> bytes:
        """Sign ``message``, returning the raw signature."""

    @abstractmethod
    def verify(
        self, public_bytes: bytes, message: bytes, signature: bytes, algorithm: str
    ) -> bool:
        """Return whether ``signature`` is valid. Never raises on a bad signature."""

    # -- KEM (optional; only needed for encrypted archives) ----------------

    def kem_generate_keypair(self, algorithm: str = "ML-KEM-768") -> KeyPair:
        """Generate a KEM key pair."""
        raise BackendUnavailableError(
            f"{self.name} does not implement key encapsulation", backend=self.name
        )

    def kem_encapsulate(self, public_bytes: bytes, algorithm: str = "ML-KEM-768") -> tuple[bytes, bytes]:
        """Return ``(shared_secret, ciphertext)``."""
        raise BackendUnavailableError(
            f"{self.name} does not implement key encapsulation", backend=self.name
        )

    def kem_decapsulate(
        self, private_bytes: bytes, ciphertext: bytes, algorithm: str = "ML-KEM-768"
    ) -> bytes:
        """Return the shared secret."""
        raise BackendUnavailableError(
            f"{self.name} does not implement key encapsulation", backend=self.name
        )


# ---------------------------------------------------------------------------
# Pure-Python FIPS 204 / FIPS 203 backend (real post-quantum cryptography)
# ---------------------------------------------------------------------------


class PyFipsBackend(CryptoBackend):
    """Real ML-DSA / ML-KEM via the ``dilithium-py`` and ``kyber-py`` packages.

    These are pure-Python implementations of FIPS 204 and FIPS 203 that pass the
    NIST known-answer tests. They interoperate byte-for-byte with OpenSSL 3.5:
    a signature produced here verifies there and vice versa.

    Caveat worth stating plainly: pure-Python code is not constant-time and is
    an order of magnitude slower than libcrypto. It is a portability and
    testability backend, not the one to pick for a busy node when OpenSSL 3.5
    is available.
    """

    name = PYFIPS_BACKEND

    def __init__(self) -> None:
        self._sig_module: Any | None = None
        self._kem_module: Any | None = None

    # -- capability probing ------------------------------------------------

    def _load_signatures(self) -> dict[str, Any] | None:
        if self._sig_module is not None:
            return self._sig_module
        try:
            from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
        except ImportError:
            return None
        self._sig_module = {
            "ML-DSA-44": ML_DSA_44,
            "ML-DSA-65": ML_DSA_65,
            "ML-DSA-87": ML_DSA_87,
        }
        return self._sig_module

    def _load_kems(self) -> dict[str, Any] | None:
        if self._kem_module is not None:
            return self._kem_module
        try:
            from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
        except ImportError:
            return None
        self._kem_module = {
            "ML-KEM-512": ML_KEM_512,
            "ML-KEM-768": ML_KEM_768,
            "ML-KEM-1024": ML_KEM_1024,
        }
        return self._kem_module

    def capabilities(self) -> Capabilities:
        """Probe for ``dilithium-py`` / ``kyber-py``."""
        signatures = self._load_signatures()
        kems = self._load_kems()
        if signatures is None and kems is None:
            return Capabilities(
                name=self.name,
                available=False,
                reason=(
                    "neither dilithium-py nor kyber-py is installed; "
                    "install with: pip install 'ics-deception[pqc]'"
                ),
            )
        version = ""
        try:
            from importlib.metadata import version as _version

            version = _version("dilithium-py")
        except Exception:  # pragma: no cover - metadata is best effort
            version = "unknown"
        return Capabilities(
            name=self.name,
            available=signatures is not None,
            signature_algorithms=tuple(signatures) if signatures else (),
            kem_algorithms=tuple(kems) if kems else (),
            provider="dilithium-py/kyber-py (pure Python FIPS 204/203)",
            version=version,
            real_pqc=True,
            reason="" if signatures else "dilithium-py is not installed",
            details={"constant_time": False, "interoperable_with_openssl": True},
        )

    # -- signatures --------------------------------------------------------

    def _signature_impl(self, algorithm: str) -> Any:
        signatures = self._load_signatures()
        if signatures is None:
            raise BackendUnavailableError(
                "dilithium-py is not installed; install with: pip install 'ics-deception[pqc]'",
                backend=self.name,
            )
        impl = signatures.get(algorithm)
        if impl is None:
            raise BackendError(
                f"{algorithm} is not supported by {self.name}; "
                f"supported: {sorted(signatures)}",
                code="unsupported_algorithm",
                backend=self.name,
            )
        return impl

    def generate_keypair(self, algorithm: str = DEFAULT_SIGNATURE_ALGORITHM) -> KeyPair:
        """Generate a real ML-DSA key pair."""
        impl = self._signature_impl(algorithm)
        public, private = impl.keygen()
        return KeyPair(
            algorithm=algorithm,
            public_bytes=bytes(public),
            private_bytes=bytes(private),
            backend=self.name,
        )

    def sign(self, private_bytes: bytes, message: bytes, algorithm: str) -> bytes:
        """Produce a real ML-DSA signature."""
        impl = self._signature_impl(algorithm)
        try:
            return bytes(impl.sign(bytes(private_bytes), bytes(message)))
        except Exception as exc:
            raise BackendError(
                f"ML-DSA signing failed: {exc}", code="sign_failed", backend=self.name
            ) from exc

    def verify(
        self, public_bytes: bytes, message: bytes, signature: bytes, algorithm: str
    ) -> bool:
        """Verify a real ML-DSA signature. A malformed signature returns False."""
        impl = self._signature_impl(algorithm)
        try:
            return bool(impl.verify(bytes(public_bytes), bytes(message), bytes(signature)))
        except Exception:
            # A truncated or corrupt signature is a verification failure, not a
            # crash: hostile input must never propagate an exception here.
            return False

    # -- key encapsulation -------------------------------------------------

    def _kem_impl(self, algorithm: str) -> Any:
        kems = self._load_kems()
        if kems is None:
            raise BackendUnavailableError(
                "kyber-py is not installed; install with: pip install 'ics-deception[pqc]'",
                backend=self.name,
            )
        impl = kems.get(algorithm)
        if impl is None:
            raise BackendError(
                f"{algorithm} is not supported by {self.name}; supported: {sorted(kems)}",
                code="unsupported_algorithm",
                backend=self.name,
            )
        return impl

    def kem_generate_keypair(self, algorithm: str = "ML-KEM-768") -> KeyPair:
        """Generate a real ML-KEM key pair."""
        impl = self._kem_impl(algorithm)
        encapsulation_key, decapsulation_key = impl.keygen()
        return KeyPair(
            algorithm=algorithm,
            public_bytes=bytes(encapsulation_key),
            private_bytes=bytes(decapsulation_key),
            backend=self.name,
        )

    def kem_encapsulate(
        self, public_bytes: bytes, algorithm: str = "ML-KEM-768"
    ) -> tuple[bytes, bytes]:
        """Encapsulate to a public key, returning ``(shared_secret, ciphertext)``."""
        impl = self._kem_impl(algorithm)
        try:
            shared_secret, ciphertext = impl.encaps(bytes(public_bytes))
        except Exception as exc:
            raise BackendError(
                f"ML-KEM encapsulation failed: {exc}",
                code="kem_encapsulate_failed",
                backend=self.name,
            ) from exc
        return bytes(shared_secret), bytes(ciphertext)

    def kem_decapsulate(
        self, private_bytes: bytes, ciphertext: bytes, algorithm: str = "ML-KEM-768"
    ) -> bytes:
        """Decapsulate a ciphertext, returning the shared secret.

        ML-KEM is designed so that a wrong key or tampered ciphertext yields an
        unpredictable secret rather than an error (implicit rejection). The
        mismatch therefore surfaces later as an AES-GCM authentication failure.
        """
        impl = self._kem_impl(algorithm)
        try:
            return bytes(impl.decaps(bytes(private_bytes), bytes(ciphertext)))
        except Exception as exc:
            raise BackendError(
                f"ML-KEM decapsulation failed: {exc}",
                code="kem_decapsulate_failed",
                backend=self.name,
            ) from exc


# ---------------------------------------------------------------------------
# Deterministic test-only backend — NOT a signature scheme
# ---------------------------------------------------------------------------


class InsecureTestBackend(CryptoBackend):
    """Deterministic stand-in for unit tests. **Provides no security.**

    It is a keyed hash (HMAC-SHA3-256) with the "public key" being the same
    secret, so anyone holding the public key can forge signatures. It exists so
    chain, registry, state and CLI logic can be tested quickly without a real
    PQC dependency — nothing more.

    Guards against misuse:

    * Only loadable when explicitly named, never by auto-selection.
    * Refuses to load when ``ICS_PQC_PRODUCTION=1``.
    * Every key it produces starts with :data:`TEST_KEY_MARKER`.
    * :attr:`Capabilities.real_pqc` is ``False``, and the signer records that
      fact in every report.
    """

    name = TEST_BACKEND

    def capabilities(self) -> Capabilities:
        """Always available, but flagged as not real post-quantum cryptography."""
        return Capabilities(
            name=self.name,
            available=not _production_mode(),
            signature_algorithms=_ML_DSA_ALGORITHMS,
            kem_algorithms=_ML_KEM_ALGORITHMS,
            provider="deterministic HMAC stand-in (NOT a signature scheme)",
            version="0",
            real_pqc=False,
            reason=(
                "refused: ICS_PQC_PRODUCTION=1 forbids the test backend"
                if _production_mode()
                else ""
            ),
            details={"security": "none", "purpose": "unit tests only"},
        )

    def _guard(self) -> None:
        if _production_mode():
            raise BackendUnavailableError(
                "the insecure test backend is disabled because ICS_PQC_PRODUCTION=1",
                backend=self.name,
            )

    def generate_keypair(self, algorithm: str = DEFAULT_SIGNATURE_ALGORITHM) -> KeyPair:
        """Generate a clearly-marked fake key pair."""
        self._guard()
        seed = TEST_KEY_MARKER + b"-" + secrets.token_bytes(32)
        return KeyPair(
            algorithm=algorithm, public_bytes=seed, private_bytes=seed, backend=self.name
        )

    def sign(self, private_bytes: bytes, message: bytes, algorithm: str) -> bytes:
        """Return a deterministic keyed digest (not a signature)."""
        self._guard()
        return hmac.new(bytes(private_bytes), bytes(message), hashlib.sha3_256).digest()

    def verify(
        self, public_bytes: bytes, message: bytes, signature: bytes, algorithm: str
    ) -> bool:
        """Recompute and compare the keyed digest."""
        self._guard()
        expected = hmac.new(bytes(public_bytes), bytes(message), hashlib.sha3_256).digest()
        return hmac.compare_digest(expected, bytes(signature))

    def kem_generate_keypair(self, algorithm: str = "ML-KEM-768") -> KeyPair:
        """Generate a clearly-marked fake KEM key pair."""
        self._guard()
        seed = TEST_KEY_MARKER + b"-kem-" + secrets.token_bytes(32)
        return KeyPair(
            algorithm=algorithm, public_bytes=seed, private_bytes=seed, backend=self.name
        )

    def kem_encapsulate(
        self, public_bytes: bytes, algorithm: str = "ML-KEM-768"
    ) -> tuple[bytes, bytes]:
        """Derive a fake shared secret from random 'ciphertext'."""
        self._guard()
        ciphertext = secrets.token_bytes(32)
        shared = hashlib.sha3_256(bytes(public_bytes) + ciphertext).digest()
        return shared, ciphertext

    def kem_decapsulate(
        self, private_bytes: bytes, ciphertext: bytes, algorithm: str = "ML-KEM-768"
    ) -> bytes:
        """Recompute the fake shared secret."""
        self._guard()
        return hashlib.sha3_256(bytes(private_bytes) + bytes(ciphertext)).digest()


def _production_mode() -> bool:
    return os.environ.get(ENV_PRODUCTION, "").strip() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Registry and selection
# ---------------------------------------------------------------------------


def _build_registry() -> dict[str, CryptoBackend]:
    from ics_deception.pqc_evidence.openssl_backend import OpenSslBackend

    return {
        OpenSslBackend.name: OpenSslBackend(),
        PyFipsBackend.name: PyFipsBackend(),
        InsecureTestBackend.name: InsecureTestBackend(),
    }


_REGISTRY: dict[str, CryptoBackend] | None = None


def _registry() -> dict[str, CryptoBackend]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build_registry()
    return _REGISTRY


#: Auto-selection order. OpenSSL first, as the specification requires preferring
#: native libcrypto; the test backend is never auto-selected.
_PREFERENCE = ("openssl", PYFIPS_BACKEND)


def get_backend(name: str) -> CryptoBackend:
    """Return a backend by name.

    Raises :class:`BackendError` for an unknown name.
    """
    backends = _registry()
    backend = backends.get(name)
    if backend is None:
        raise BackendError(
            f"unknown crypto backend {name!r}; available: {sorted(backends)}",
            code="unknown_backend",
        )
    return backend


def available_backends() -> list[Capabilities]:
    """Probe every backend and return its capabilities, preferred first."""
    backends = _registry()
    ordered = [*_PREFERENCE, TEST_BACKEND]
    return [backends[name].capabilities() for name in ordered if name in backends]


def detect_private_key_backend(private_bytes: bytes) -> str:
    """Infer which backend can consume a private key, from its encoding.

    **Public** keys are raw algorithm bytes and are fully interoperable between
    backends. **Private** keys are not: OpenSSL stores a PKCS#8 PEM structure,
    while the pure-Python backend uses the raw FIPS 204/203 private key. Handing
    one to the other produces a confusing decoder error deep inside OpenSSL, so
    the format is detected up front and the matching backend is selected.
    """
    if private_bytes.lstrip()[:11] == b"-----BEGIN ":
        return "openssl"
    if private_bytes.startswith(TEST_KEY_MARKER):
        return TEST_BACKEND
    return PYFIPS_BACKEND


def select_backend(
    name: str | None = None,
    algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
    allow_test_backend: bool = False,
    require_kem: str | None = None,
    for_private_key: bytes | None = None,
) -> CryptoBackend:
    """Choose a backend that can actually perform the requested operation.

    ``name`` (or ``ICS_PQC_BACKEND``) forces a specific backend and fails loudly
    if it cannot do the job. Otherwise, when ``for_private_key`` is supplied the
    backend that owns that key's format is used; failing that, the first capable
    backend in preference order wins. The test backend is never chosen
    implicitly.
    """
    requested = name or os.environ.get(ENV_BACKEND) or None

    if requested is None and for_private_key:
        detected = detect_private_key_backend(for_private_key)
        if detected == TEST_BACKEND and not allow_test_backend:
            raise BackendUnavailableError(
                "this private key is marked INSECURE-TEST-ONLY; refusing to use it "
                "without allow_test_backend=True",
                backend=TEST_BACKEND,
            )
        backend = get_backend(detected)
        capabilities = backend.capabilities()
        if capabilities.available and capabilities.supports_signature(algorithm):
            return backend
        raise BackendUnavailableError(
            f"this private key is in the {detected!r} format but that backend is "
            f"unavailable: {capabilities.reason or 'unsupported algorithm'}",
            backend=detected,
        )

    if requested:
        backend = get_backend(requested)
        if requested == TEST_BACKEND and not allow_test_backend:
            raise BackendUnavailableError(
                f"backend {TEST_BACKEND!r} provides no security and must be requested "
                "explicitly by a test (allow_test_backend=True)",
                backend=requested,
            )
        capabilities = backend.capabilities()
        if not capabilities.available:
            raise BackendUnavailableError(
                f"backend {requested!r} is unavailable: {capabilities.reason}",
                backend=requested,
            )
        if not capabilities.supports_signature(algorithm):
            raise BackendUnavailableError(
                f"backend {requested!r} does not support {algorithm}; "
                f"supported: {sorted(capabilities.signature_algorithms)}",
                backend=requested,
            )
        if require_kem and not capabilities.supports_kem(require_kem):
            raise BackendUnavailableError(
                f"backend {requested!r} does not support {require_kem}",
                backend=requested,
            )
        return backend

    problems: list[str] = []
    for candidate in _PREFERENCE:
        backend = _registry()[candidate]
        capabilities = backend.capabilities()
        if not capabilities.available:
            problems.append(f"{candidate}: {capabilities.reason or 'unavailable'}")
            continue
        if not capabilities.supports_signature(algorithm):
            problems.append(f"{candidate}: does not support {algorithm}")
            continue
        if require_kem and not capabilities.supports_kem(require_kem):
            problems.append(f"{candidate}: does not support {require_kem}")
            continue
        return backend

    raise BackendUnavailableError(
        f"no backend can provide {algorithm}"
        + (f" and {require_kem}" if require_kem else "")
        + ". Tried:\n  - "
        + "\n  - ".join(problems)
        + "\nInstall a portable implementation with: pip install 'ics-deception[pqc]'"
        + "\nor install OpenSSL 3.5 or newer for the native backend."
    )


def select_real_backend(
    signature_algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
    kem_algorithm: str | None = None,
    require_real_crypto: bool = True,
    name: str | None = None,
) -> CryptoBackend:
    """Select a backend by **capability**, not by name.

    This is what generic tests and callers should use: "give me something that
    can really do ML-DSA-65" rather than "give me pyfips". Naming an optional
    backend means the whole suite fails when that one package is missing, even
    though a perfectly good native OpenSSL is present.

    Preference order is :data:`_PREFERENCE` — native OpenSSL first, then the
    portable pure-Python implementation. ``require_real_crypto`` refuses the
    deterministic test backend outright.

    Raises :class:`BackendUnavailableError` with a per-backend explanation when
    nothing qualifies.
    """
    return select_backend(
        name=name,
        algorithm=signature_algorithm,
        allow_test_backend=not require_real_crypto,
        require_kem=kem_algorithm,
    )


def real_backends(
    signature_algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
    kem_algorithm: str | None = None,
) -> list[CryptoBackend]:
    """Return every *real* backend able to perform the requested operations.

    Lets a test matrix run the same generic assertions against each available
    real implementation, instead of picking one and hoping.
    """
    found: list[CryptoBackend] = []
    for candidate in _PREFERENCE:
        backend = _registry()[candidate]
        capabilities = backend.capabilities()
        if not (capabilities.available and capabilities.real_pqc):
            continue
        if not capabilities.supports_signature(signature_algorithm):
            continue
        if kem_algorithm and not capabilities.supports_kem(kem_algorithm):
            continue
        found.append(backend)
    return found


def describe_capabilities() -> dict[str, Any]:
    """Return a machine-readable capability report for every backend."""
    capabilities = available_backends()
    real = [c for c in capabilities if c.available and c.real_pqc]
    return {
        "default_signature_algorithm": DEFAULT_SIGNATURE_ALGORITHM,
        "production_mode": _production_mode(),
        "real_pqc_available": bool(real),
        "preferred_backend": real[0].name if real else None,
        "backends": [c.to_dict() for c in capabilities],
    }
