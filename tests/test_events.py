"""Tests for JSONL event creation and event field structure."""

from __future__ import annotations

import json
from datetime import datetime

from ics_deception.common.events import MAX_DETAIL_STRING, Event, EventPublisher


def test_event_has_the_four_required_fields():
    event = Event(source="unit-test", event_type="probe", details={"a": 1})
    payload = event.to_dict()

    assert list(payload) == ["timestamp", "source", "event_type", "details"]
    assert payload["source"] == "unit-test"
    assert payload["event_type"] == "probe"
    assert payload["details"] == {"a": 1}


def test_event_timestamp_is_timezone_aware_utc():
    event = Event(source="unit-test", event_type="probe")
    parsed = datetime.fromisoformat(event.timestamp)

    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_to_json_is_a_single_line():
    event = Event(source="s", event_type="t", details={"multi": "line\nbreak"})
    line = event.to_json()

    assert "\n" not in line
    assert json.loads(line)["details"]["multi"] == "line\nbreak"


def test_emit_appends_one_json_object_per_line(event_log):
    publisher = EventPublisher(source="unit-test", echo=False)

    publisher.emit("first", index=1)
    publisher.emit("second", index=2)

    lines = event_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    records = [json.loads(line) for line in lines]
    assert [record["event_type"] for record in records] == ["first", "second"]
    assert all(record["source"] == "unit-test" for record in records)
    assert [record["details"]["index"] for record in records] == [1, 2]


def test_emit_creates_the_log_directory_lazily(tmp_path):
    target = tmp_path / "nested" / "deeper" / "events.jsonl"
    publisher = EventPublisher(source="unit-test", log_path=target, echo=False)

    publisher.emit("created")

    assert target.is_file()


def test_helper_levels_set_a_message_detail(event_log):
    publisher = EventPublisher(source="unit-test", echo=False)

    publisher.info("hello")
    publisher.warning("careful")
    publisher.error("broken")

    records = [
        json.loads(line) for line in event_log.read_text(encoding="utf-8").strip().splitlines()
    ]
    assert [record["event_type"] for record in records] == ["info", "warning", "error"]
    assert [record["details"]["message"] for record in records] == ["hello", "careful", "broken"]


def test_attacker_supplied_strings_are_truncated(event_log):
    publisher = EventPublisher(source="unit-test", echo=False)

    publisher.emit("flood", payload="A" * (MAX_DETAIL_STRING * 4))

    record = json.loads(event_log.read_text(encoding="utf-8").strip())
    assert record["details"]["payload"].endswith("...[truncated]")
    assert len(record["details"]["payload"]) < MAX_DETAIL_STRING * 2


def test_bytes_details_are_hex_encoded(event_log):
    publisher = EventPublisher(source="unit-test", echo=False)

    publisher.emit("raw", frame=b"\x00\x01\xff")

    record = json.loads(event_log.read_text(encoding="utf-8").strip())
    assert record["details"]["frame"] == "0001ff"
