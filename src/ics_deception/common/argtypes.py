"""Reusable ``argparse`` type validators.

``argparse`` accepts ``--max-packets 0`` or ``--timeout -5`` happily when the
type is just ``int``/``float``, which then silently disables a limit or makes a
socket time out immediately. Every bounded numeric option in this project goes
through one of these validators, so out-of-range input is rejected at parse
time with a clear message and exit code 2.
"""

from __future__ import annotations

import argparse
import math
from collections.abc import Callable

__all__ = [
    "bounded_float",
    "bounded_int",
    "non_negative_int",
    "port_number",
    "positive_float",
    "positive_int",
    "register_address",
]


def bounded_int(minimum: int, maximum: int | None = None) -> Callable[[str], int]:
    """Return an ``argparse`` type accepting integers in ``[minimum, maximum]``."""

    def parse(text: str) -> int:
        try:
            value = int(text, 10)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
        if value < minimum or (maximum is not None and value > maximum):
            upper = maximum if maximum is not None else "unbounded"
            raise argparse.ArgumentTypeError(
                f"{value} is out of range (expected {minimum}..{upper})"
            )
        return value

    return parse


def bounded_float(minimum: float, maximum: float | None = None) -> Callable[[str], float]:
    """Return an ``argparse`` type accepting finite floats in ``[minimum, maximum]``."""

    def parse(text: str) -> float:
        try:
            value = float(text)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
        # Reject NaN and infinities: both defeat every subsequent range check.
        if math.isnan(value) or math.isinf(value):
            raise argparse.ArgumentTypeError(f"{text!r} is not a finite number")
        if value < minimum or (maximum is not None and value > maximum):
            upper = maximum if maximum is not None else "unbounded"
            raise argparse.ArgumentTypeError(
                f"{value} is out of range (expected {minimum}..{upper})"
            )
        return value

    return parse


def positive_int(text: str) -> int:
    """Parse an integer strictly greater than zero."""
    return bounded_int(1)(text)


def non_negative_int(text: str) -> int:
    """Parse an integer greater than or equal to zero."""
    return bounded_int(0)(text)


def positive_float(text: str) -> float:
    """Parse a finite float strictly greater than zero."""
    value = bounded_float(0.0)(text)
    if value == 0.0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return value


def port_number(text: str) -> int:
    """Parse a TCP port in ``1..65535``.

    Port 0 is rejected for user-facing options: it means "let the kernel
    choose", which is useful inside tests but never what an operator intends.
    """
    return bounded_int(1, 65535)(text)


def register_address(text: str) -> int:
    """Parse a 16-bit Modbus register or coil address."""
    return bounded_int(0, 0xFFFF)(text)
