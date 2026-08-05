"""Canonical JSON test vectors and rejection rules."""

from __future__ import annotations

import pytest

from ics_deception.pqc_evidence.canonicalizer import (
    MAX_DEPTH,
    CanonicalizationError,
    canonical_bytes,
    canonical_string,
    check_canonicalizable,
    normalize_timestamp,
)

# -- test vectors -----------------------------------------------------------

VECTORS = [
    ({}, b"{}"),
    ({"a": 1}, b'{"a":1}'),
    ({"b": 2, "a": 1}, b'{"a":1,"b":2}'),
    ({"z": [1, 2, 3]}, b'{"z":[1,2,3]}'),
    ({"n": None, "t": True, "f": False}, b'{"f":false,"n":null,"t":true}'),
    ({"nested": {"y": 1, "x": 2}}, b'{"nested":{"x":2,"y":1}}'),
    ({"unicode": "ü"}, '{"unicode":"ü"}'.encode()),
    ({"empty_list": [], "empty_obj": {}}, b'{"empty_list":[],"empty_obj":{}}'),
    ({"neg": -42, "big": 2**53}, b'{"big":9007199254740992,"neg":-42}'),
]


@pytest.mark.parametrize(("value", "expected"), VECTORS)
def test_canonical_test_vectors(value, expected):
    assert canonical_bytes(value) == expected


def test_output_is_utf8_not_escaped_ascii():
    encoded = canonical_bytes({"k": "ü"})

    assert b"\\u" not in encoded
    assert encoded.decode("utf-8") == '{"k":"ü"}'


def test_no_trailing_newline_or_whitespace():
    encoded = canonical_bytes({"a": 1, "b": [1, 2]})

    assert not encoded.endswith(b"\n")
    assert b", " not in encoded
    assert b": " not in encoded


# -- equivalence ------------------------------------------------------------


def test_key_order_does_not_change_canonical_bytes():
    first = {"b": 2, "a": 1, "c": {"z": 1, "y": 2}}
    second = {"c": {"y": 2, "z": 1}, "a": 1, "b": 2}

    assert canonical_bytes(first) == canonical_bytes(second)


def test_whitespace_in_the_source_document_is_irrelevant():
    import json

    spaced = json.loads('{ "a" : 1 ,\n  "b" :  [ 1 , 2 ]  }')
    compact = json.loads('{"a":1,"b":[1,2]}')

    assert canonical_bytes(spaced) == canonical_bytes(compact)


def test_any_value_change_changes_the_bytes():
    base = {"register": 40001, "value": 1}

    assert canonical_bytes(base) != canonical_bytes({"register": 40001, "value": 2})
    assert canonical_bytes(base) != canonical_bytes({"register": 40002, "value": 1})
    assert canonical_bytes(base) != canonical_bytes({"register": 40001, "value": "1"})


def test_list_order_is_significant():
    assert canonical_bytes({"a": [1, 2]}) != canonical_bytes({"a": [2, 1]})


def test_tuples_and_lists_canonicalize_identically():
    assert canonical_bytes({"a": (1, 2)}) == canonical_bytes({"a": [1, 2]})


# -- rejection --------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        {"f": 1.5},
        {"f": 1.0},
        {"f": float("nan")},
        {"f": float("inf")},
        {"f": float("-inf")},
        {"b": b"bytes"},
        {"s": {1, 2}},
        {1: "non-string key"},
        {"t": object()},
    ],
)
def test_unsupported_values_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


def test_error_message_points_at_the_offending_path():
    with pytest.raises(CanonicalizationError, match=r"\$\.outer\.inner"):
        canonical_bytes({"outer": {"inner": 1.5}})


def test_excessive_nesting_is_rejected():
    deep: dict = {}
    cursor = deep
    for _ in range(MAX_DEPTH + 5):
        cursor["next"] = {}
        cursor = cursor["next"]

    with pytest.raises(CanonicalizationError, match="nesting deeper"):
        canonical_bytes(deep)


def test_lone_surrogates_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"bad": "\ud800"})


def test_check_canonicalizable_accepts_valid_documents():
    check_canonicalizable({"a": [1, {"b": None}], "c": "text"})


def test_canonical_string_matches_canonical_bytes():
    value = {"b": 1, "a": "ü"}

    assert canonical_string(value).encode("utf-8") == canonical_bytes(value)


# -- timestamps -------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("2026-08-05T18:15:00Z", "2026-08-05T18:15:00.000000Z"),
        ("2026-08-05T18:15:00+00:00", "2026-08-05T18:15:00.000000Z"),
        ("2026-08-05T20:15:00+02:00", "2026-08-05T18:15:00.000000Z"),
        ("2026-08-05T13:15:00-05:00", "2026-08-05T18:15:00.000000Z"),
        ("2026-08-05T18:15:00.123456Z", "2026-08-05T18:15:00.123456Z"),
        ("  2026-08-05T18:15:00Z  ", "2026-08-05T18:15:00.000000Z"),
    ],
)
def test_timestamps_normalize_to_one_utc_spelling(given, expected):
    assert normalize_timestamp(given) == expected


def test_equivalent_instants_produce_identical_canonical_bytes():
    utc = normalize_timestamp("2026-08-05T18:15:00Z")
    offset = normalize_timestamp("2026-08-05T20:15:00+02:00")

    assert canonical_bytes({"timestamp": utc}) == canonical_bytes({"timestamp": offset})


@pytest.mark.parametrize(
    "value",
    ["", "not a timestamp", "2026-08-05T18:15:00", "2026-13-45T99:99:99Z", "2026/08/05 18:15"],
)
def test_invalid_or_naive_timestamps_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        normalize_timestamp(value)


def test_naive_timestamp_message_explains_the_requirement():
    with pytest.raises(CanonicalizationError, match="no timezone"):
        normalize_timestamp("2026-08-05T18:15:00")
