"""Fixtures for the evidence tests.

Backends are requested by **capability**, never by name. Naming an optional
package means the whole suite fails when that one package is missing, even
though a perfectly good native OpenSSL is present. Tests skip only when *no*
real post-quantum provider exists at all, and say so explicitly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ics_deception.pqc_evidence.crypto_backend import (
    BackendUnavailableError,
    CryptoBackend,
    KeyPair,
    real_backends,
    select_real_backend,
)
from ics_deception.pqc_evidence.key_registry import KeyRegistry
from ics_deception.pqc_evidence.signer import EvidenceSigner

NODE_ID = "rpi-honeypot-01"
KEY_ID = "rpi-honeypot-01-2026-01"


def _require(signature: str = "ML-DSA-65", kem: str | None = None) -> CryptoBackend:
    """Return any real backend with the requested capabilities, or skip."""
    try:
        return select_real_backend(
            signature_algorithm=signature, kem_algorithm=kem, require_real_crypto=True
        )
    except BackendUnavailableError as exc:
        pytest.skip(
            f"no real post-quantum backend provides {signature}"
            + (f" and {kem}" if kem else "")
            + f": {exc}. Install with: pip install 'ics-deception[pqc]', "
            "or install OpenSSL 3.5 or newer."
        )


@pytest.fixture(scope="session")
def pqc_backend() -> CryptoBackend:
    """Any real ML-DSA backend — OpenSSL if present, otherwise the portable one."""
    return _require("ML-DSA-65")


@pytest.fixture(scope="session")
def kem_backend() -> CryptoBackend:
    """Any real ML-KEM-768 backend."""
    return _require("ML-DSA-65", "ML-KEM-768")


@pytest.fixture(
    scope="session",
    params=[b.name for b in real_backends("ML-DSA-65")] or ["none-available"],
)
def every_real_backend(request) -> CryptoBackend:
    """Parametrised over *every* available real backend.

    Generic cryptographic assertions run against each real implementation
    present, rather than against one arbitrarily chosen name.
    """
    if request.param == "none-available":
        pytest.skip("no real post-quantum backend is installed")
    from ics_deception.pqc_evidence.crypto_backend import get_backend

    return get_backend(request.param)


@pytest.fixture(scope="session")
def openssl_backend() -> CryptoBackend:
    """The native OpenSSL backend specifically, or an explicit skip."""
    from ics_deception.pqc_evidence.crypto_backend import get_backend

    backend = get_backend("openssl")
    capabilities = backend.capabilities()
    if not capabilities.available:
        pytest.skip(f"native OpenSSL ML-DSA unavailable: {capabilities.reason}")
    return backend


@pytest.fixture(scope="session")
def signing_keypair(pqc_backend: CryptoBackend) -> KeyPair:
    """One ML-DSA-65 key pair reused across the session (keygen is slow)."""
    return pqc_backend.generate_keypair("ML-DSA-65")


@pytest.fixture(scope="session")
def other_keypair(pqc_backend: CryptoBackend) -> KeyPair:
    """A second, unrelated key pair for wrong-key tests."""
    return pqc_backend.generate_keypair("ML-DSA-65")


@pytest.fixture(scope="session")
def kem_keypair(kem_backend: CryptoBackend) -> KeyPair:
    """One ML-KEM-768 key pair reused across the session."""
    return kem_backend.kem_generate_keypair("ML-KEM-768")


@pytest.fixture
def registry(signing_keypair: KeyPair) -> KeyRegistry:
    """A registry trusting the session signing key from the epoch onward."""
    reg = KeyRegistry()
    reg.register(
        key_id=KEY_ID,
        node_id=NODE_ID,
        public_key=signing_keypair.public_bytes,
        activated_at="2000-01-01T00:00:00Z",
    )
    return reg


@pytest.fixture
def evidence_path(tmp_path: Path) -> Path:
    """The evidence log this signer writes to."""
    return tmp_path / "evidence.jsonl"


@pytest.fixture
def signer(
    tmp_path: Path,
    evidence_path: Path,
    signing_keypair: KeyPair,
    pqc_backend: CryptoBackend,
) -> EvidenceSigner:
    """A signer writing chain state and evidence into a temporary directory."""
    return EvidenceSigner(
        node_id=NODE_ID,
        key_id=KEY_ID,
        private_key=signing_keypair.private_bytes,
        state_path=tmp_path / "state.json",
        evidence_path=evidence_path,
        backend=pqc_backend,
    )


@pytest.fixture
def sample_events() -> list[dict]:
    """A short, representative run of honeypot events."""
    return [
        {
            "source": "modbus_honeypot",
            "event_type": "critical_register_write",
            "client_ip": "192.168.1.50",
            "register": 40001,
            "value": 1,
        },
        {
            "source": "dnp3_sensor",
            "event_type": "dnp3_interaction",
            "client_ip": "192.168.1.50",
            "length": 16,
        },
        {
            "source": "fake_ssh_banner",
            "event_type": "login_attempt",
            "username": "admin",
            "password_length": 8,
        },
        {"source": "fake_telnet", "event_type": "telnet_command", "command": "status"},
        {"source": "controller", "event_type": "component_started", "name": "modbus_native"},
    ]


@pytest.fixture
def signed_lines(signer: EvidenceSigner, sample_events: list[dict]) -> list[str]:
    """A valid five-record signed chain, as JSONL text."""
    return [signer.sign_event(event).to_json_line() for event in sample_events]


def tamper(line: str, **changes) -> str:
    """Return ``line`` with top-level envelope fields replaced."""
    record = json.loads(line)
    record.update(changes)
    return json.dumps(record, separators=(",", ":"), sort_keys=True)


def tamper_event(line: str, **changes) -> str:
    """Return ``line`` with fields inside the nested ``event`` replaced."""
    record = json.loads(line)
    record["event"].update(changes)
    return json.dumps(record, separators=(",", ":"), sort_keys=True)
