
"""Common JSON event logging utilities and schema helpers."""
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


LOG_DIR = os.environ.get("ICS_LOG_DIR", "data/logs")
os.makedirs(LOG_DIR, exist_ok=True)




def utc_now_iso() -> str:
return datetime.now(timezone.utc).isoformat()




def _open_log(path: str):
os.makedirs(os.path.dirname(path), exist_ok=True)
return open(path, "a", encoding="utf-8")




def make_event(
*,
source: str,
dest: str,
proto: str,
msg_type: str,
meta: Optional[Dict[str, Any]] = None,
payload_hex: Optional[str] = None,
) -> Dict[str, Any]:
return {
"ts": utc_now_iso(),
"source": source,
"dest": dest,
"proto": proto,
"msg_type": msg_type, # e.g., request|response|read|write|heartbeat
"payload_hex": payload_hex,
"meta": meta or {},
}




def log_event(event: Dict[str, Any], *, filename: str = "events.jsonl") -> None:
path = os.path.join(LOG_DIR, filename)
with _open_log(path) as f:
f.write(json.dumps(event, ensure_ascii=False) + "
")
