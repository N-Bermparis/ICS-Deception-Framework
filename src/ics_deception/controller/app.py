"""FastAPI controller for the deception fabric.

Binds to ``127.0.0.1`` by default and starts **nothing** automatically: a
component runs only when it is both ``enabled`` in the configuration and either
marked ``autostart`` or started explicitly through the API.

Endpoints
---------
``GET  /health``                     liveness and configuration summary
``GET  /status``                     per-component supervision state
``GET  /logs``                       tail of the JSONL event log, parsed
``GET  /ics-values``                 last fake PLC reading
``POST /components/{name}/start``    start one component
``POST /components/{name}/stop``     stop one component
``POST /replay``                     controlled PCAP replay (one at a time)

The controller has **no authentication**. See ``SECURITY.md``: it must not be
exposed beyond loopback without an authenticating reverse proxy and network
controls.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ics_deception import __version__
from ics_deception.common.events import EventPublisher
from ics_deception.common.paths import (
    ensure_dir,
    event_log_path,
    pcap_dir,
    plc_state_path,
    runtime_dir,
)
from ics_deception.common.publisher import create_event_publisher, evidence_status
from ics_deception.controller.config import ControllerConfig, default_config
from ics_deception.controller.process import ProcessSupervisor
from ics_deception.datasets.pcap_utils import (
    PcapNotFoundError,
    PcapTraversalError,
    UnsupportedCaptureError,
    validate_pcap_path,
)

__all__ = ["ReplayRequest", "create_app", "project_root"]


def project_root() -> Path:
    """Return the repository root (``src/ics_deception/controller`` → up three)."""
    return Path(__file__).resolve().parents[3]


class ReplayRequest(BaseModel):
    """Body of ``POST /replay``."""

    model_config = {"extra": "forbid"}

    #: Path to the capture. Relative paths resolve inside the approved directory.
    pcap_path: str = Field(min_length=1)
    #: Upper bound on processed packets; clamped to the configured maximum.
    max_packets: int | None = Field(default=None, ge=1)
    modbus_target: str = "127.0.0.1:5020"
    dnp3_target: str = "127.0.0.1:20000"


class ReplayManager:
    """Serialises PCAP replay: at most one job may run at a time."""

    def __init__(self, publisher: EventPublisher) -> None:
        self.publisher = publisher
        self._lock = threading.Lock()
        self._active: dict | None = None
        self._proc: subprocess.Popen | None = None

    @property
    def active(self) -> dict | None:
        """Return a description of the running job, or ``None``."""
        with self._lock:
            if self._proc is not None and self._proc.poll() is not None:
                self._active = None
                self._proc = None
            return dict(self._active) if self._active else None

    def start(self, argv: list[str], cwd: Path, log_path: Path, description: dict) -> bool:
        """Start a replay job. Returns ``False`` if one is already running."""
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return False
            ensure_dir(log_path.parent)
            # Not a context manager: the handle must outlive this scope and stay
            # open for as long as the replay subprocess is writing to it.
            handle = open(log_path, "ab", buffering=0)  # noqa: SIM115
            try:
                self._proc = subprocess.Popen(  # noqa: S603 - argv is built from validated input
                    argv,
                    cwd=str(cwd),
                    stdin=subprocess.DEVNULL,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                )
            except OSError:
                handle.close()
                raise
            self._active = {**description, "pid": self._proc.pid, "log_file": str(log_path)}
            threading.Thread(
                target=self._reap, args=(self._proc, handle), daemon=True
            ).start()
            return True

    def _reap(self, proc: subprocess.Popen, handle) -> None:
        """Wait for the job to finish, then release the slot."""
        returncode = proc.wait()
        with self._lock:
            if self._proc is proc:
                self._proc = None
                self._active = None
        with contextlib.suppress(OSError):
            handle.close()
        self.publisher.emit("replay_finished", returncode=returncode)

    def stop(self) -> None:
        """Terminate a running job (used on controller shutdown)."""
        with self._lock:
            proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover
                proc.kill()


def create_app(
    config: ControllerConfig | None = None,
    publisher: EventPublisher | None = None,
    root: Path | None = None,
) -> FastAPI:
    """Build the controller application.

    Passing an explicit ``config``/``publisher``/``root`` makes the app fully
    injectable, which is what the test-suite uses.
    """
    config = config if config is not None else default_config()
    publisher = (
        publisher if publisher is not None else create_event_publisher(source="controller")
    )
    root = (root if root is not None else project_root()).resolve()

    supervisor = ProcessSupervisor(config.components, root, publisher)
    replays = ReplayManager(publisher)

    # Config wins when set; otherwise fall back to ICS_DECEPTION_PCAP_DIR.
    if config.pcap_dir:
        approved_dir = Path(config.pcap_dir).expanduser()
        approved_dir = (
            approved_dir.resolve()
            if approved_dir.is_absolute()
            else (root / approved_dir).resolve()
        )
    else:
        approved_dir = pcap_dir()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        publisher.emit(
            "controller_startup",
            host=config.host,
            port=config.port,
            components=supervisor.names(),
            autostart=[
                name for name, c in config.components.items() if c.enabled and c.autostart
            ],
        )
        # Only components explicitly marked enabled AND autostart are launched.
        started = supervisor.start_autostart()
        if started:
            publisher.emit("controller_autostart", results=started)
        try:
            yield
        finally:
            publisher.emit("controller_shutdown")
            replays.stop()
            supervisor.stop_all()

    app = FastAPI(
        title="ICS Deception Framework Controller",
        version=__version__,
        description=(
            "Research prototype controller for an ICS deception fabric. "
            "No authentication: bind to loopback only."
        ),
        lifespan=lifespan,
    )
    app.state.config = config
    app.state.supervisor = supervisor
    app.state.replays = replays
    app.state.publisher = publisher
    app.state.project_root = root
    app.state.approved_pcap_dir = approved_dir

    # -- endpoints --------------------------------------------------------

    @app.get("/health")
    def health() -> JSONResponse:
        """Liveness probe and a summary of the effective configuration."""
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "host": config.host,
                "port": config.port,
                "components": supervisor.names(),
                "enabled_components": sorted(config.enabled_components()),
                "approved_pcap_dir": str(approved_dir),
                "event_log": str(event_log_path()),
                "replay_active": replays.active is not None,
            }
        )

    @app.get("/status")
    def status() -> JSONResponse:
        """Per-component supervision state, plus evidence-layer status.

        The evidence block reports the mode, node/key identifiers, backend,
        chain position and counters. It never contains key material.
        """
        return JSONResponse(
            {
                "components": supervisor.status(),
                "replay": replays.active,
                "evidence": evidence_status(),
            }
        )

    @app.get("/logs")
    def logs(limit: int = Query(100, ge=1, le=5000)) -> JSONResponse:
        """Return the last ``limit`` events as **parsed JSON objects**.

        Lines that fail to parse are returned as ``{"_unparsed": "..."}`` rather
        than being silently dropped, so corruption stays visible.
        """
        path = event_log_path()
        if not path.is_file():
            return JSONResponse({"logs": [], "count": 0, "event_log": str(path)})
        try:
            # Stream through a bounded deque instead of readlines(): the event
            # log is append-only and can reach gigabytes on a long-running
            # sensor, and loading it whole to return the last 100 records would
            # let a large log OOM the controller.
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = deque(handle, maxlen=limit)
        except OSError as exc:  # pragma: no cover - permission failure
            raise HTTPException(status_code=500, detail=f"cannot read event log: {exc}") from exc

        parsed: list[dict] = []
        for line in lines:
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                parsed.append({"_unparsed": text[:1000]})
                continue
            parsed.append(obj if isinstance(obj, dict) else {"_unparsed": text[:1000]})
        return JSONResponse({"logs": parsed, "count": len(parsed), "event_log": str(path)})

    @app.get("/ics-values")
    def ics_values() -> JSONResponse:
        """Return the fake PLC's last reading, written atomically by the node."""
        path = plc_state_path()
        if not path.is_file():
            raise HTTPException(
                status_code=404,
                detail="no PLC state available; is the fake_plc component running?",
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=503, detail=f"PLC state unreadable: {exc}"
            ) from exc
        return JSONResponse(data)

    @app.post("/components/{name}/start")
    def start_component(name: str) -> JSONResponse:
        """Start one configured component."""
        process = supervisor.get(name)
        if process is None:
            raise HTTPException(status_code=404, detail=f"unknown component: {name}")
        if not process.config.enabled:
            raise HTTPException(
                status_code=409, detail=f"component {name!r} is disabled in configuration"
            )
        ok = supervisor.start(name)
        if not ok:
            raise HTTPException(
                status_code=500,
                detail=f"failed to start {name}: {process.last_error or 'unknown error'}",
            )
        return JSONResponse({"started": name, "status": process.info()})

    @app.post("/components/{name}/stop")
    def stop_component(name: str) -> JSONResponse:
        """Stop one configured component."""
        process = supervisor.get(name)
        if process is None:
            raise HTTPException(status_code=404, detail=f"unknown component: {name}")
        ok = supervisor.stop(name)
        if not ok:
            raise HTTPException(status_code=500, detail=f"failed to stop {name}")
        return JSONResponse({"stopped": name, "status": process.info()})

    @app.post("/replay")
    def replay(request: ReplayRequest) -> JSONResponse:
        """Replay a capture from the approved directory to laboratory targets.

        Status codes: ``400`` unsupported extension, ``403`` path traversal,
        ``404`` missing capture, ``409`` a replay is already running.
        """
        publisher.emit("replay_requested", pcap_path=request.pcap_path)
        try:
            capture = validate_pcap_path(request.pcap_path, approved_dir)
        except UnsupportedCaptureError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PcapTraversalError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except PcapNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        max_packets = min(
            request.max_packets or config.max_replay_packets, config.max_replay_packets
        )
        log_path = runtime_dir() / "replay.log"
        argv = [
            sys.executable,
            "-m",
            "ics_deception.datasets.pcap_loader",
            "--pcap",
            str(capture),
            "--approved-dir",
            str(approved_dir),
            "--replay",
            "--max-packets",
            str(max_packets),
            "--modbus-target",
            request.modbus_target,
            "--dnp3-target",
            request.dnp3_target,
        ]
        description = {
            "pcap": str(capture),
            "max_packets": max_packets,
            "modbus_target": request.modbus_target,
            "dnp3_target": request.dnp3_target,
        }
        try:
            accepted = replays.start(argv, root, log_path, description)
        except OSError as exc:  # pragma: no cover - spawn failure
            raise HTTPException(status_code=500, detail=f"cannot start replay: {exc}") from exc
        if not accepted:
            raise HTTPException(
                status_code=409, detail="a replay job is already running; retry when it finishes"
            )
        publisher.emit("replay_started", **description)
        return JSONResponse({"status": "replay_started", **(replays.active or description)})

    return app
