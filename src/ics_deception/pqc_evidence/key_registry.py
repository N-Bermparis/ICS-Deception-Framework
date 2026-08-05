"""Trusted-node public-key registry.

A verifier needs to answer one question for every record: *was this signed by a
key that this node was legitimately using at that moment?* The registry holds
the public half of every node key, its lifecycle state, and the window during
which it was valid.

Only **public** keys live here. The registry file is designed to be copied to an
analyst workstation, committed to an internal repository, or shipped with an
evidence archive without exposing anything secret.

Key lifecycle::

    active     the node's current signing key
    rotated    superseded by a newer key; historical events still verify
    revoked    compromised or withdrawn; events signed by it are NOT trusted
    expired    past its expiry time (also detected from the timestamps)
    disabled   administratively switched off

Rotation preserves history: rotating marks the old key ``rotated`` rather than
deleting it, so events it signed keep verifying, while new events must use the
new ``active`` key.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ics_deception.pqc_evidence import DEFAULT_SIGNATURE_ALGORITHM, EvidenceError
from ics_deception.pqc_evidence.canonicalizer import normalize_timestamp
from ics_deception.pqc_evidence.models import (
    MAX_NODE_ID_LENGTH,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    EvidenceValidationError,
)

__all__ = [
    "KeyRecord",
    "KeyRegistry",
    "KeyRegistryError",
    "KeyState",
    "KeyUsability",
    "fingerprint",
]

#: Registry file format version.
REGISTRY_FORMAT_VERSION = "1.0"

#: Upper bound on a registry file, to stop a hostile file exhausting memory.
MAX_REGISTRY_BYTES = 8 * 1024 * 1024


class KeyRegistryError(EvidenceError):
    """The registry is invalid, or an operation on it is not permitted."""


class KeyState(str, Enum):
    """Lifecycle state of a registered key."""

    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"
    DISABLED = "disabled"


def fingerprint(public_key: bytes) -> str:
    """Return a short, stable fingerprint of a raw public key.

    SHA3-256 of the raw key bytes, rendered as colon-separated hex pairs of the
    first 8 bytes — long enough to compare by eye, and the full digest is
    available in :attr:`KeyRecord.public_key_sha3_256`.
    """
    digest = hashlib.sha3_256(public_key).digest()
    return ":".join(f"{byte:02x}" for byte in digest[:8])


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _parse_time(value: str, field_name: str) -> datetime:
    try:
        normalized = normalize_timestamp(value)
    except Exception as exc:
        raise KeyRegistryError(f"{field_name} is not a valid UTC timestamp: {exc}") from exc
    return datetime.strptime(normalized, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


@dataclass
class KeyRecord:
    """One registered public key."""

    key_id: str
    node_id: str
    algorithm: str
    #: Base64 of the raw algorithm-level public key (1952 bytes for ML-DSA-65).
    public_key: str
    created_at: str
    activated_at: str
    expires_at: str | None = None
    state: KeyState = KeyState.ACTIVE
    revocation_reason: str | None = None
    revoked_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- derived ----------------------------------------------------------

    @property
    def public_key_bytes(self) -> bytes:
        """Decode the raw public key, raising on malformed base64."""
        try:
            return base64.b64decode(self.public_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeyRegistryError(
                f"key {self.key_id!r} has an invalid base64 public key: {exc}"
            ) from exc

    @property
    def public_key_sha3_256(self) -> str:
        """Full SHA3-256 digest of the raw public key."""
        return hashlib.sha3_256(self.public_key_bytes).hexdigest()

    @property
    def fingerprint(self) -> str:
        """Short human-comparable fingerprint."""
        return fingerprint(self.public_key_bytes)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable record."""
        data = asdict(self)
        data["state"] = self.state.value
        data["fingerprint"] = self.fingerprint
        data["public_key_sha3_256"] = self.public_key_sha3_256
        return data

    @staticmethod
    def from_dict(data: Any) -> KeyRecord:
        """Validate and build a record from untrusted JSON."""
        if not isinstance(data, dict):
            raise KeyRegistryError("key record must be a JSON object")
        required = {"key_id", "node_id", "algorithm", "public_key", "created_at", "activated_at"}
        missing = required - set(data)
        if missing:
            raise KeyRegistryError(f"key record is missing field(s): {sorted(missing)}")

        for name in ("key_id", "node_id"):
            value = data[name]
            if not isinstance(value, str) or not value or len(value) > MAX_NODE_ID_LENGTH:
                raise KeyRegistryError(f"key record has an invalid {name}")

        algorithm = data["algorithm"]
        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise KeyRegistryError(
                f"key {data['key_id']!r} uses unsupported algorithm {algorithm!r}"
            )

        state_value = data.get("state", KeyState.ACTIVE.value)
        try:
            state = KeyState(state_value)
        except ValueError as exc:
            raise KeyRegistryError(f"unknown key state {state_value!r}") from exc

        record = KeyRecord(
            key_id=data["key_id"],
            node_id=data["node_id"],
            algorithm=algorithm,
            public_key=data["public_key"],
            created_at=data["created_at"],
            activated_at=data["activated_at"],
            expires_at=data.get("expires_at"),
            state=state,
            revocation_reason=data.get("revocation_reason"),
            revoked_at=data.get("revoked_at"),
            metadata=data.get("metadata") or {},
        )
        if not isinstance(record.metadata, dict):
            raise KeyRegistryError(f"key {record.key_id!r} has non-object metadata")
        # Force validation of the encoded key and of every timestamp; the
        # properties raise on malformed input, which is the point.
        _ = record.public_key_bytes
        _parse_time(record.created_at, "created_at")
        _parse_time(record.activated_at, "activated_at")
        if record.expires_at is not None:
            _parse_time(record.expires_at, "expires_at")
        return record


@dataclass(frozen=True)
class KeyUsability:
    """Whether a key may be used, and why not if it may not."""

    usable: bool
    #: Stable machine-readable problem codes (see the ``pqc_*`` alert names).
    problems: tuple[str, ...] = ()
    detail: str = ""


class KeyRegistry:
    """A collection of trusted public keys, persisted as JSON.

    The in-memory registry is the source of truth; :meth:`save` writes it out
    atomically so a crash mid-write can never leave a truncated registry.
    """

    def __init__(self, records: list[KeyRecord] | None = None) -> None:
        self._records: dict[str, KeyRecord] = {}
        for record in records or []:
            self._insert(record)

    # -- construction ------------------------------------------------------

    def _insert(self, record: KeyRecord) -> None:
        existing = self._records.get(record.key_id)
        if existing is not None:
            if existing.node_id != record.node_id or existing.public_key != record.public_key:
                raise KeyRegistryError(
                    f"conflicting definitions for key_id {record.key_id!r}: "
                    f"node {existing.node_id!r}/{record.node_id!r}"
                )
            raise KeyRegistryError(f"duplicate key_id {record.key_id!r}")
        # The same public key registered under two identifiers is almost always
        # a copy/paste error and would make revocation incomplete.
        for other in self._records.values():
            if other.public_key == record.public_key:
                raise KeyRegistryError(
                    f"public key of {record.key_id!r} is already registered as {other.key_id!r}"
                )
        self._records[record.key_id] = record

    @staticmethod
    def load(path: str | Path) -> KeyRegistry:
        """Load a registry from disk. A missing file yields an empty registry."""
        registry_path = Path(path).expanduser()
        if not registry_path.is_file():
            return KeyRegistry()
        try:
            size = registry_path.stat().st_size
        except OSError as exc:
            raise KeyRegistryError(f"cannot stat registry {registry_path}: {exc}") from exc
        if size > MAX_REGISTRY_BYTES:
            raise KeyRegistryError(
                f"registry {registry_path} is {size} bytes, exceeding the "
                f"{MAX_REGISTRY_BYTES} byte limit"
            )
        try:
            raw = registry_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise KeyRegistryError(f"cannot read registry {registry_path}: {exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise KeyRegistryError(f"registry {registry_path} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise KeyRegistryError("registry must be a JSON object")
        version = data.get("format_version")
        if version != REGISTRY_FORMAT_VERSION:
            raise KeyRegistryError(
                f"unsupported registry format_version {version!r}; "
                f"expected {REGISTRY_FORMAT_VERSION!r}"
            )
        entries = data.get("keys")
        if not isinstance(entries, list):
            raise KeyRegistryError("registry 'keys' must be a list")
        return KeyRegistry([KeyRecord.from_dict(entry) for entry in entries])

    def save(self, path: str | Path) -> Path:
        """Write the registry atomically with restrictive permissions."""
        registry_path = Path(path).expanduser()
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format_version": REGISTRY_FORMAT_VERSION,
            "updated_at": _utc_now(),
            "keys": [record.to_dict() for record in self.sorted_records()],
        }
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - atomic replace needs the name
            mode="w",
            encoding="utf-8",
            dir=str(registry_path.parent),
            prefix=f".{registry_path.name}.",
            suffix=".tmp",
            delete=False,
        )
        temporary = handle.name
        try:
            with handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o644)  # public keys: world-readable is fine
            os.replace(temporary, registry_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise
        return registry_path

    # -- queries -----------------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, key_id: object) -> bool:
        return key_id in self._records

    def sorted_records(self) -> list[KeyRecord]:
        """All records, ordered by node then key identifier."""
        return sorted(self._records.values(), key=lambda r: (r.node_id, r.key_id))

    def get(self, key_id: str) -> KeyRecord | None:
        """Return a record by key identifier, or ``None``."""
        return self._records.get(key_id)

    def nodes(self) -> list[str]:
        """Every node identifier that has at least one registered key."""
        return sorted({record.node_id for record in self._records.values()})

    def for_node(self, node_id: str) -> list[KeyRecord]:
        """Every key registered for a node, newest activation first."""
        records = [r for r in self._records.values() if r.node_id == node_id]
        return sorted(records, key=lambda r: r.activated_at, reverse=True)

    def active_key(self, node_id: str) -> KeyRecord | None:
        """The node's current signing key, if it has one."""
        for record in self.for_node(node_id):
            if record.state is KeyState.ACTIVE:
                return record
        return None

    # -- mutation ----------------------------------------------------------

    def register(
        self,
        key_id: str,
        node_id: str,
        public_key: bytes,
        algorithm: str = DEFAULT_SIGNATURE_ALGORITHM,
        activated_at: str | None = None,
        expires_at: str | None = None,
        metadata: dict[str, Any] | None = None,
        make_active: bool = True,
    ) -> KeyRecord:
        """Register a new public key for a node.

        When ``make_active`` is set, any previously active key for that node is
        marked ``rotated`` — history keeps verifying, new events must use the
        new key.
        """
        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise KeyRegistryError(f"unsupported algorithm {algorithm!r}")
        if not public_key:
            raise KeyRegistryError("public key must not be empty")

        now = _utc_now()
        record = KeyRecord(
            key_id=key_id,
            node_id=node_id,
            algorithm=algorithm,
            public_key=base64.b64encode(public_key).decode("ascii"),
            created_at=now,
            activated_at=normalize_timestamp(activated_at) if activated_at else now,
            expires_at=normalize_timestamp(expires_at) if expires_at else None,
            state=KeyState.ACTIVE if make_active else KeyState.DISABLED,
            metadata=metadata or {},
        )
        # Validate through the same path untrusted input takes.
        record = KeyRecord.from_dict(record.to_dict())

        if make_active:
            previous = self.active_key(node_id)
            if previous is not None:
                previous.state = KeyState.ROTATED
        self._insert(record)
        return record

    def revoke(self, key_id: str, reason: str) -> KeyRecord:
        """Revoke a key. Events signed by it stop being trusted."""
        record = self._require(key_id)
        if not reason or not reason.strip():
            raise KeyRegistryError("a revocation reason is required")
        record.state = KeyState.REVOKED
        record.revocation_reason = reason.strip()
        record.revoked_at = _utc_now()
        return record

    def disable(self, key_id: str) -> KeyRecord:
        """Administratively disable a key without declaring it compromised."""
        record = self._require(key_id)
        record.state = KeyState.DISABLED
        return record

    def rotate(self, node_id: str, new_key_id: str, public_key: bytes, **kwargs: Any) -> KeyRecord:
        """Register a new active key for a node, rotating the previous one."""
        if self.active_key(node_id) is None and not self.for_node(node_id):
            raise KeyRegistryError(
                f"node {node_id!r} has no registered key to rotate; register one first"
            )
        return self.register(new_key_id, node_id, public_key, make_active=True, **kwargs)

    def _require(self, key_id: str) -> KeyRecord:
        record = self._records.get(key_id)
        if record is None:
            raise KeyRegistryError(f"unknown key_id {key_id!r}")
        return record

    # -- verification support ---------------------------------------------

    def check_usable(
        self, key_id: str, node_id: str, at: str, algorithm: str
    ) -> KeyUsability:
        """Decide whether ``key_id`` could legitimately have signed for ``node_id`` at ``at``.

        Returns a structured result rather than raising, because the verifier
        needs to report *every* problem it finds, not just the first.
        """
        record = self._records.get(key_id)
        if record is None:
            known_node = any(r.node_id == node_id for r in self._records.values())
            if not known_node:
                return KeyUsability(
                    False,
                    ("pqc_unknown_node", "pqc_unknown_key"),
                    f"node {node_id!r} and key {key_id!r} are both unknown to the registry",
                )
            return KeyUsability(
                False, ("pqc_unknown_key",), f"key {key_id!r} is not in the registry"
            )

        problems: list[str] = []
        details: list[str] = []

        if record.node_id != node_id:
            problems.append("pqc_unknown_node")
            details.append(
                f"key {key_id!r} belongs to node {record.node_id!r}, not {node_id!r}"
            )
        if record.algorithm != algorithm:
            problems.append("pqc_unsupported_algorithm")
            details.append(
                f"key {key_id!r} is registered for {record.algorithm}, event claims {algorithm}"
            )
        if record.state is KeyState.REVOKED:
            problems.append("pqc_revoked_key")
            details.append(
                f"key {key_id!r} was revoked"
                + (f": {record.revocation_reason}" if record.revocation_reason else "")
            )
        if record.state is KeyState.DISABLED:
            problems.append("pqc_revoked_key")
            details.append(f"key {key_id!r} is disabled")

        try:
            event_time = _parse_time(at, "event timestamp")
            activated = _parse_time(record.activated_at, "activated_at")
            if event_time < activated:
                problems.append("pqc_unknown_key")
                details.append(
                    f"event at {at} precedes key activation at {record.activated_at}"
                )
            if record.expires_at is not None:
                expires = _parse_time(record.expires_at, "expires_at")
                if event_time > expires:
                    problems.append("pqc_expired_key")
                    details.append(f"event at {at} is after key expiry at {record.expires_at}")
            if record.state is KeyState.EXPIRED and "pqc_expired_key" not in problems:
                problems.append("pqc_expired_key")
                details.append(f"key {key_id!r} is marked expired")
        except KeyRegistryError as exc:
            problems.append("pqc_malformed_evidence")
            details.append(str(exc))

        return KeyUsability(not problems, tuple(problems), "; ".join(details))

    # -- import / export ---------------------------------------------------

    def export_public(self) -> dict[str, Any]:
        """Return the public registry document (already secret-free)."""
        return {
            "format_version": REGISTRY_FORMAT_VERSION,
            "exported_at": _utc_now(),
            "keys": [record.to_dict() for record in self.sorted_records()],
        }

    def import_public(self, document: Any, overwrite: bool = False) -> list[str]:
        """Merge exported entries, returning the key identifiers added."""
        if not isinstance(document, dict):
            raise KeyRegistryError("import document must be a JSON object")
        if document.get("format_version") != REGISTRY_FORMAT_VERSION:
            raise KeyRegistryError(
                f"unsupported import format_version {document.get('format_version')!r}"
            )
        entries = document.get("keys")
        if not isinstance(entries, list):
            raise KeyRegistryError("import document 'keys' must be a list")

        added: list[str] = []
        for entry in entries:
            record = KeyRecord.from_dict(entry)
            if record.key_id in self._records:
                if not overwrite:
                    continue
                del self._records[record.key_id]
            self._insert(record)
            added.append(record.key_id)
        return added


def load_public_key_file(path: str | Path) -> bytes:
    """Read a raw or base64 public key from ``path``.

    Accepts either raw bytes or base64 text, so a key can be moved by copying a
    file or by pasting a line. Anything else raises
    :class:`EvidenceValidationError`.
    """
    key_path = Path(path).expanduser()
    if not key_path.is_file():
        raise EvidenceValidationError(f"public key file not found: {key_path}")
    data = key_path.read_bytes()
    if not data:
        raise EvidenceValidationError(f"public key file is empty: {key_path}")
    try:
        text = data.strip().decode("ascii")
    except UnicodeDecodeError:
        return data  # raw binary key
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return data  # ASCII, but not base64: treat as raw bytes
