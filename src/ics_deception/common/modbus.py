"""Minimal Modbus/TCP framing helpers.

This module implements only the framing and the handful of function codes the
framework needs. It is **not** a complete or standards-compliant Modbus
implementation and must not be used to talk to real field equipment.

MBAP header layout (7 bytes)::

    0-1  transaction identifier
    2-3  protocol identifier (0x0000 for Modbus)
    4-5  length          (number of following bytes: unit id + PDU)
    6    unit identifier

The ``length`` field is what makes stream reassembly possible: a complete
Application Data Unit is ``MBAP_HEADER_LEN - 1 + length`` bytes long.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "EXC_ILLEGAL_DATA_ADDRESS",
    "EXC_ILLEGAL_DATA_VALUE",
    "EXC_ILLEGAL_FUNCTION",
    "EXC_SERVER_DEVICE_FAILURE",
    "FC_READ_COILS",
    "FC_READ_HOLDING_REGISTERS",
    "FC_WRITE_MULTIPLE_REGISTERS",
    "FC_WRITE_SINGLE_COIL",
    "FC_WRITE_SINGLE_REGISTER",
    "MAX_ADU_LEN",
    "MAX_MBAP_LENGTH",
    "MAX_PDU_LEN",
    "MIN_MBAP_LENGTH",
    "MBAP_HEADER_LEN",
    "MODBUS_PROTOCOL_ID",
    "MbapHeader",
    "is_valid_mbap",
    "build_exception_response",
    "build_read_holding_registers_request",
    "build_response",
    "build_write_single_register_request",
    "parse_mbap",
]

MBAP_HEADER_LEN = 7
MODBUS_PROTOCOL_ID = 0x0000

#: Largest legal PDU (function code + data) per the Modbus/TCP specification.
MAX_PDU_LEN = 253
#: Largest legal Application Data Unit: MBAP header + PDU.
MAX_ADU_LEN = MBAP_HEADER_LEN + MAX_PDU_LEN

# The MBAP ``length`` field counts the unit identifier *plus* the PDU, so it is
# always one larger than the PDU length. Getting this off by one silently drops
# maximum-size frames, so the bounds live here and every component imports them
# rather than hard-coding a number.
#: Smallest legal MBAP length value: unit id + a one-byte PDU (function code).
MIN_MBAP_LENGTH = 2
#: Largest legal MBAP length value: unit id + a maximum-size PDU (1 + 253).
MAX_MBAP_LENGTH = MAX_PDU_LEN + 1

FC_READ_COILS = 0x01
FC_READ_HOLDING_REGISTERS = 0x03
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10

EXC_ILLEGAL_FUNCTION = 0x01
EXC_ILLEGAL_DATA_ADDRESS = 0x02
EXC_ILLEGAL_DATA_VALUE = 0x03
EXC_SERVER_DEVICE_FAILURE = 0x04


@dataclass(frozen=True)
class MbapHeader:
    """A parsed MBAP header."""

    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int

    @property
    def total_frame_len(self) -> int:
        """Total ADU size in bytes, header included."""
        return MBAP_HEADER_LEN - 1 + self.length

    @property
    def pdu_len(self) -> int:
        """Length of the PDU (function code + data)."""
        return self.length - 1


def parse_mbap(data: bytes) -> MbapHeader | None:
    """Parse an MBAP header, or return ``None`` if fewer than 7 bytes are present.

    The caller is responsible for validating the returned fields; this function
    performs no semantic checks so that malformed frames can be logged.
    """
    if len(data) < MBAP_HEADER_LEN:
        return None
    return MbapHeader(
        transaction_id=int.from_bytes(data[0:2], "big"),
        protocol_id=int.from_bytes(data[2:4], "big"),
        length=int.from_bytes(data[4:6], "big"),
        unit_id=data[6],
    )


def is_valid_mbap(header: MbapHeader) -> bool:
    """Return whether an MBAP header's protocol id and length are in range.

    Shared by the Python server and the PCAP analyser so that the accepted
    frame sizes cannot drift apart between components.
    """
    if header.protocol_id != MODBUS_PROTOCOL_ID:
        return False
    return MIN_MBAP_LENGTH <= header.length <= MAX_MBAP_LENGTH


def build_response(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Wrap ``pdu`` in an MBAP header with a correctly computed length field."""
    length = len(pdu) + 1  # unit id + PDU
    return (
        transaction_id.to_bytes(2, "big")
        + MODBUS_PROTOCOL_ID.to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + bytes([unit_id & 0xFF])
        + pdu
    )


def build_exception_response(
    transaction_id: int, unit_id: int, function_code: int, exception_code: int
) -> bytes:
    """Build an exact-size (9 byte) Modbus exception response.

    No bytes from the offending request are copied into the reply.
    """
    pdu = bytes([(function_code | 0x80) & 0xFF, exception_code & 0xFF])
    return build_response(transaction_id, unit_id, pdu)


def build_read_holding_registers_request(
    transaction_id: int, unit_id: int, address: int, quantity: int
) -> bytes:
    """Build a well-formed FC03 (Read Holding Registers) request."""
    pdu = (
        bytes([FC_READ_HOLDING_REGISTERS])
        + address.to_bytes(2, "big")
        + quantity.to_bytes(2, "big")
    )
    return build_response(transaction_id, unit_id, pdu)


def build_write_single_register_request(
    transaction_id: int, unit_id: int, address: int, value: int
) -> bytes:
    """Build a well-formed FC06 (Write Single Register) request."""
    pdu = (
        bytes([FC_WRITE_SINGLE_REGISTER])
        + address.to_bytes(2, "big")
        + value.to_bytes(2, "big")
    )
    return build_response(transaction_id, unit_id, pdu)
