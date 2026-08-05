"""Validated controller configuration.

Configuration is JSON, loaded through Pydantic models so that a malformed or
hostile file is rejected with a clear error rather than being handed to
``subprocess`` verbatim.

Two component kinds exist:

``python``
    ``args`` are passed to the *currently running* interpreter
    (``sys.executable``). This keeps a virtual environment's interpreter in
    play instead of whatever ``python3`` happens to be first on ``PATH``.

``binary``
    ``command[0]`` names an executable. A relative path is resolved against the
    project root and must exist and be executable *before* the process is
    started; it may not escape the project root. An absolute path is allowed
    but must exist — this is a deliberate escape hatch for system binaries.

Nothing starts automatically: every component defaults to ``enabled: false``
and ``autostart: false``.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

__all__ = [
    "ComponentConfig",
    "ControllerConfig",
    "ConfigError",
    "default_config",
    "load_config",
    "write_default_config",
]


class ConfigError(RuntimeError):
    """Raised when the controller configuration is missing or invalid."""


class ComponentConfig(BaseModel):
    """One supervised child process."""

    model_config = {"extra": "forbid"}

    kind: Literal["python", "binary"]
    #: Interpreter arguments for ``kind == "python"``, e.g. ``["-m", "pkg.mod"]``.
    args: list[str] = Field(default_factory=list)
    #: Full argv for ``kind == "binary"``.
    command: list[str] = Field(default_factory=list)
    enabled: bool = False
    autostart: bool = False
    description: str = ""

    @field_validator("args", "command")
    @classmethod
    def _no_empty_tokens(cls, value: list[str]) -> list[str]:
        for token in value:
            if not isinstance(token, str) or not token.strip():
                raise ValueError("command tokens must be non-empty strings")
        return value

    def validate_shape(self, name: str) -> None:
        """Check that the fields required by this component's kind are present."""
        if self.kind == "python" and not self.args:
            raise ValueError(f"component {name!r}: kind 'python' requires non-empty 'args'")
        if self.kind == "binary" and not self.command:
            raise ValueError(f"component {name!r}: kind 'binary' requires non-empty 'command'")
        if self.kind == "python" and self.command:
            raise ValueError(f"component {name!r}: kind 'python' must not set 'command'")
        if self.kind == "binary" and self.args:
            raise ValueError(f"component {name!r}: kind 'binary' must not set 'args'")

    def resolve_executable(self, project_root: Path) -> Path | None:
        """Validate and return the executable path for a ``binary`` component.

        Returns ``None`` for ``python`` components, whose executable is
        ``sys.executable`` and needs no validation.

        Raises
        ------
        ValueError
            The path escapes the project root, does not exist, is not a
            regular file, or is not executable.
        """
        if self.kind != "binary":
            return None

        raw = Path(self.command[0])
        if raw.is_absolute():
            candidate = raw.resolve()
        else:
            root = project_root.resolve()
            candidate = (root / raw).resolve()
            if root not in candidate.parents and candidate != root:
                raise ValueError(
                    f"executable path escapes the project root: {candidate} not under {root}"
                )

        if not candidate.is_file():
            raise ValueError(f"executable not found: {candidate}")
        if os.name != "nt" and not os.access(candidate, os.X_OK):
            raise ValueError(f"executable is not executable: {candidate}")
        return candidate


class ControllerConfig(BaseModel):
    """Top-level controller configuration."""

    model_config = {"extra": "forbid"}

    #: Loopback by default. Exposing the controller requires an explicit change
    #: *and* the authentication / network controls described in SECURITY.md.
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    #: Only captures inside this directory may be replayed. A relative path is
    #: resolved against the project root. When omitted, the directory comes from
    #: ``ICS_DECEPTION_PCAP_DIR`` (default ``./data/pcaps``), so setting it here
    #: overrides the environment.
    pcap_dir: str | None = None
    #: Upper bound handed to the replay subprocess.
    max_replay_packets: int = Field(default=5000, ge=1, le=1_000_000)
    components: dict[str, ComponentConfig] = Field(default_factory=dict)

    @field_validator("components")
    @classmethod
    def _validate_components(
        cls, value: dict[str, ComponentConfig]
    ) -> dict[str, ComponentConfig]:
        for name, component in value.items():
            if not name or not name.replace("-", "").replace("_", "").isalnum():
                raise ValueError(
                    f"invalid component name {name!r}: use alphanumerics, '-' and '_' only"
                )
            component.validate_shape(name)
        return value

    def enabled_components(self) -> dict[str, ComponentConfig]:
        """Return only the components that are enabled."""
        return {name: c for name, c in self.components.items() if c.enabled}

    def describe_command(self, name: str) -> str:
        """Return a shell-quoted, human-readable form of a component's command."""
        component = self.components[name]
        tokens = component.command if component.kind == "binary" else ["<python>", *component.args]
        return " ".join(shlex.quote(token) for token in tokens)


def default_config() -> ControllerConfig:
    """Return the shipped default configuration.

    Every component is disabled; an operator opts in explicitly.
    """
    return ControllerConfig(
        components={
            "modbus_python": ComponentConfig(
                kind="python",
                args=[
                    "-m",
                    "ics_deception.honeypots.modbus_server",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "5020",
                ],
                enabled=False,
                autostart=False,
                description="Standard-library Modbus/TCP deception server (FC03/FC06 subset)",
            ),
            "modbus_native": ComponentConfig(
                kind="binary",
                command=[
                    "build/modbus_honeypot",
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    "5020",
                ],
                enabled=False,
                autostart=False,
                description="Native C++ Modbus/TCP honeypot (build with 'make build')",
            ),
            "dnp3": ComponentConfig(
                kind="python",
                args=[
                    "-m",
                    "ics_deception.honeypots.dnp3_sensor",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "20000",
                ],
                enabled=False,
                autostart=False,
                description="DNP3-inspired interaction sensor (NOT a DNP3 outstation)",
            ),
            "fake_plc": ComponentConfig(
                kind="python",
                args=[
                    "-m",
                    "ics_deception.iot_nodes.fake_plc",
                    "--target-host",
                    "127.0.0.1",
                    "--target-port",
                    "5020",
                    "--interval",
                    "30",
                ],
                enabled=False,
                autostart=False,
                description="Fake PLC node polling the Modbus honeypot with valid FC03 requests",
            ),
        }
    )


def load_config(path: str | Path | None) -> ControllerConfig:
    """Load and validate a configuration file.

    ``None`` or a missing file yields :func:`default_config` — the controller
    starts with everything disabled rather than refusing to boot.
    """
    if path is None:
        return default_config()
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        return default_config()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read controller config {config_path}: {exc}") from exc
    try:
        return ControllerConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid controller config {config_path}:\n{exc}") from exc


def write_default_config(path: str | Path) -> Path:
    """Write the default configuration to ``path`` and return the path."""
    config_path = Path(path).expanduser()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(default_config().model_dump(), indent=2) + "\n", encoding="utf-8"
    )
    return config_path
