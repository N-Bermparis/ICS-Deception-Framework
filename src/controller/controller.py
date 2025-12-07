#!/usr/bin/env python3
"""
controller/controller.py

Central controller:
  - Orchestrates Python honeypots (DNP3, fake PLC)
  - Can optionally start C++ honeypot binaries (paths from config)
  - Exposes REST API via FastAPI:
      /status       - component status
      /logs         - tail of events.jsonl
      /replay       - trigger pcap replay
      /ics-values   - read last fake PLC state
"""

import json
import os
import signal
import subprocess
import threading
import time
from typing import Dict, List, Optional

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import uvicorn

from common.events import EventPublisher, EVENT_LOG_PATH

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logging")
os.makedirs(LOG_DIR, exist_ok=True)

CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

publisher = EventPublisher(source="controller")


class ManagedProcess:
    def __init__(self, name: str, cmd: List[str], cwd: Optional[str] = None):
        self.name = name
        self.cmd = cmd
        self.cwd = cwd
        self.proc: Optional[subprocess.Popen] = None

    def start(self):
        if self.proc and self.proc.poll() is None:
            return
        publisher.info("starting_process", name=self.name, cmd=self.cmd)
        self.proc = subprocess.Popen(
            self.cmd,
            cwd=self.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def stop(self):
        if not self.proc:
            return
        if self.proc.poll() is None:
            publisher.info("stopping_process", name=self.name)
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def status(self) -> str:
        if self.proc is None:
            return "stopped"
        if self.proc.poll() is None:
            return "running"
        return f"exited({self.proc.returncode})"


class Controller:
    def __init__(self):
        self.config = self.load_config()
        self.processes: Dict[str, ManagedProcess] = {}
        self._lock = threading.Lock()
        self._setup_processes()

    def load_config(self) -> Dict:
        if not os.path.exists(CONFIG_PATH):
            # Minimal default config
            default = {
                "honeypots": {
                    "dnp3": {
                        "type": "python",
                        "cmd": ["python3", "honeypots/dnp3_honeypot.py"],
                    },
                    "fake_plc": {
                        "type": "python",
                        "cmd": ["python3", "iot-nodes/raspberrypi/fake_plc.py"],
                    },
                    # Example C++ modbus honeypot binary path
                    "modbus": {
                        "type": "binary",
                        "cmd": ["./honeypots/modbus_honeypot"],
                    },
                }
            }
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(default, f, indent=2)
            return default
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def _setup_processes(self):
        for name, cfg in self.config.get("honeypots", {}).items():
            cmd = cfg["cmd"]
            self.processes[name] = ManagedProcess(name, cmd, cwd=BASE_DIR)

    def start_all(self):
        with self._lock:
            for mp in self.processes.values():
                mp.start()

    def stop_all(self):
        with self._lock:
            for mp in self.processes.values():
                mp.stop()

    def status(self) -> Dict[str, str]:
        with self._lock:
            return {name: mp.status() for name, mp in self.processes.items()}

    def start(self, name: str):
        with self._lock:
            if name in self.processes:
                self.processes[name].start()

    def stop(self, name: str):
        with self._lock:
            if name in self.processes:
                self.processes[name].stop()


controller = Controller()
app = FastAPI(title="ICS Honeypot Controller", version="1.0.0")


@app.on_event("startup")
async def startup_event():
    publisher.info("controller_startup")
    # Start core services by default
    controller.start_all()


@app.on_event("shutdown")
async def shutdown_event():
    publisher.info("controller_shutdown")
    controller.stop_all()


@app.get("/status")
def api_status():
    return JSONResponse({"status": controller.status()})


@app.get("/logs")
def api_logs(limit: int = Query(100, ge=1, le=5000)):
    if not os.path.exists(EVENT_LOG_PATH):
        return JSONResponse({"logs": []})
    with open(EVENT_LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return JSONResponse({"logs": [l.strip() for l in lines[-limit:]]})


@app.post("/replay")
def api_replay(pcap_path: str):
    """
    Trigger PCAP replay via datasets/pcap4sics_loader.py
    """
    publisher.info("replay_requested", pcap_path=pcap_path)
    script = os.path.join(BASE_DIR, "datasets", "pcap4sics_loader.py")
    if not os.path.exists(script):
        return JSONResponse({"error": "pcap4sics_loader.py not found"}, status_code=500)

    # Fire-and-forget; could be async or a background task
    subprocess.Popen(["python3", script, "--replay", "--pcap", pcap_path], cwd=BASE_DIR)
    return JSONResponse({"status": "replay_started"})


@app.get("/ics-values")
def api_ics_values():
    plc_state_path = os.path.join(LOG_DIR, "plc_state.json")
    if not os.path.exists(plc_state_path):
        return JSONResponse({"error": "no_plc_state"}, status_code=404)
    with open(plc_state_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(data)


def run_console():
    """
    Very simple console dashboard printing status periodically.
    Run in a separate thread if desired.
    """
    while True:
        st = controller.status()
        print("\n=== Honeypot Status ===")
        for name, state in st.items():
            print(f"  {name:10s}: {state}")
        time.sleep(10)


if __name__ == "__main__":
    # Optional: run console in another thread
    t = threading.Thread(target=run_console, daemon=True)
    t.start()

    uvicorn.run(app, host="0.0.0.0", port=8000)

