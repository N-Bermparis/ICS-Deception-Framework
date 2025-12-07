#!/usr/bin/env python3
"""
common/events.py

Central event bus & JSON logger for the honeypot framework.
All Python modules should use EventPublisher to emit structured events.

Logs:
  - Main event log: logging/events.jsonl (one JSON per line)
"""

import json
import os
import sys
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logging")
os.makedirs(LOG_DIR, exist_ok=True)

EVENT_LOG_PATH = os.path.join(LOG_DIR, "events.jsonl")


@dataclass
class Event:
    timestamp: str
    source: str
    event_type: str
    details: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class EventPublisher:
    """
    Simple thread-safe JSON line logger.

    Optionally, you can add:
      - Remote log shipping (HTTP, syslog, Kafka) later.
    """

    _lock = threading.Lock()

    def __init__(self, source: str = "core"):
        self.source = source

    def emit(self, event_type: str, **details: Any) -> None:
        evt = Event(
            timestamp=datetime.utcnow().isoformat() + "Z",
            source=self.source,
            event_type=event_type,
            details=details,
        )
        line = evt.to_json()
        with self._lock:
            with open(EVENT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        # Optional: also to stdout
        print(line, file=sys.stdout, flush=True)

    def info(self, msg: str, **details: Any) -> None:
        details.setdefault("message", msg)
        self.emit("info", **details)

    def warning(self, msg: str, **details: Any) -> None:
        details.setdefault("message", msg)
        self.emit("warning", **details)

    def error(self, msg: str, **details: Any) -> None:
        details.setdefault("message", msg)
        self.emit("error", **details)


# Global default publisher for simple usage
default_publisher = EventPublisher(source="global")

def emit(event_type: str, **details: Any) -> None:
    default_publisher.emit(event_type, **details)
