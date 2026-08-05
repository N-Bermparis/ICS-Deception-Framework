"""Command-line entry point for the controller (``ics-controller``)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from ics_deception.common.argtypes import port_number
from ics_deception.common.publisher import create_event_publisher
from ics_deception.controller.app import create_app, project_root
from ics_deception.controller.config import ConfigError, load_config, write_default_config

__all__ = ["main"]

DEFAULT_CONFIG = "config/controller.json"


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ics-controller",
        description=(
            "ICS Deception Framework controller. Binds to loopback by default and "
            "has NO authentication — do not expose it without a network control plane."
        ),
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG, help=f"controller config (default: {DEFAULT_CONFIG})"
    )
    parser.add_argument("--host", default=None, help="override the configured bind address")
    parser.add_argument(
        "--port", type=port_number, default=None, help="override the configured port (1..65535)"
    )
    parser.add_argument("--log", default=None, help="JSONL event log path override")
    parser.add_argument(
        "--write-default-config",
        metavar="PATH",
        default=None,
        help="write the default configuration to PATH and exit",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Start the controller under uvicorn."""
    args = _parse_args(argv)

    if args.write_default_config:
        path = write_default_config(args.write_default_config)
        print(f"wrote default configuration to {path}")
        return 0

    root = project_root()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.host is not None:
        config.host = args.host
    if args.port is not None:
        config.port = args.port

    publisher = create_event_publisher(source="controller", log_path=args.log)
    app = create_app(config=config, publisher=publisher, root=root)

    if config.host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"WARNING: controller is binding to {config.host}, not loopback. "
            "It has no authentication — see SECURITY.md.",
            file=sys.stderr,
        )

    import uvicorn  # local import so --write-default-config works without uvicorn

    uvicorn.run(app, host=config.host, port=config.port, log_level="info")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
