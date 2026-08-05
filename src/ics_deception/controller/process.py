"""Supervision of child deception services.

Design notes
------------
* Child stdout/stderr go to a **per-component log file**, never to
  ``subprocess.PIPE``. An unread pipe fills its OS buffer and blocks the child
  — the original prototype's most likely production hang.
* Children are started in their **own process group** (POSIX ``start_new_session``,
  Windows ``CREATE_NEW_PROCESS_GROUP``) so that a service which spawns helpers
  can be signalled as a unit and cannot be killed by a Ctrl-C aimed at the
  controller.
* Shutdown escalates SIGTERM → SIGKILL against the whole group.
* A start failure is captured and reported; it never propagates out and kills
  the controller.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

from ics_deception.common.events import EventPublisher
from ics_deception.common.paths import component_log_path, ensure_dir
from ics_deception.controller.config import ComponentConfig

__all__ = ["ManagedProcess", "ProcessSupervisor"]

#: Seconds to wait for a graceful exit before escalating to SIGKILL.
TERM_GRACE_SECONDS = 5.0

_POSIX = os.name != "nt"


class ManagedProcess:
    """A single supervised child process."""

    def __init__(
        self,
        name: str,
        config: ComponentConfig,
        project_root: Path,
        publisher: EventPublisher,
    ) -> None:
        self.name = name
        self.config = config
        self.project_root = project_root
        self.publisher = publisher
        self.proc: subprocess.Popen | None = None
        self.last_error: str | None = None
        self._log_handle = None

    # -- introspection ----------------------------------------------------

    @property
    def log_path(self) -> Path:
        """Path of this component's stdout/stderr log file."""
        return component_log_path(self.name)

    def build_argv(self) -> list[str]:
        """Return the argv to execute, validating any relative executable path.

        Raises ``ValueError`` if the configured executable fails validation.
        """
        if self.config.kind == "python":
            # Use the interpreter that is running the controller, so a venv is honoured.
            return [sys.executable, *self.config.args]
        executable = self.config.resolve_executable(self.project_root)
        assert executable is not None  # kind == "binary" always resolves
        return [str(executable), *self.config.command[1:]]

    def status(self) -> str:
        """Return ``running``, ``stopped``, ``exited(<code>)`` or ``failed``."""
        if self.proc is None:
            return "failed" if self.last_error else "stopped"
        code = self.proc.poll()
        if code is None:
            return "running"
        return f"exited({code})"

    def info(self) -> dict:
        """Return a JSON-serialisable status record."""
        return {
            "name": self.name,
            "kind": self.config.kind,
            "enabled": self.config.enabled,
            "autostart": self.config.autostart,
            "description": self.config.description,
            "status": self.status(),
            "pid": self.proc.pid if self.proc and self.proc.poll() is None else None,
            "log_file": str(self.log_path),
            "last_error": self.last_error,
        }

    # -- lifecycle --------------------------------------------------------

    def start(self) -> bool:
        """Start the child process. Returns ``True`` on success.

        Never raises: failures are recorded in ``last_error`` and emitted as an
        event, so one broken component cannot take down the controller.
        """
        if self.proc is not None and self.proc.poll() is None:
            return True
        if not self.config.enabled:
            self.last_error = "component is disabled in configuration"
            self.publisher.emit("component_start_refused", name=self.name, reason=self.last_error)
            return False

        try:
            argv = self.build_argv()
        except ValueError as exc:
            self.last_error = str(exc)
            self.publisher.emit("component_start_failed", name=self.name, error=self.last_error)
            return False

        log_path = self.log_path
        try:
            ensure_dir(log_path.parent)
            # Not a context manager: the handle is the child's stdout/stderr and
            # must stay open for the lifetime of the process.
            handle = open(log_path, "ab", buffering=0)  # noqa: SIM115
        except OSError as exc:
            self.last_error = f"cannot open component log {log_path}: {exc}"
            self.publisher.emit("component_start_failed", name=self.name, error=self.last_error)
            return False

        creation_kwargs: dict = {}
        if _POSIX:
            # New session => new process group, detached from the controller's.
            creation_kwargs["start_new_session"] = True
        else:  # pragma: no cover - Windows deployments are not the target
            creation_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            self.proc = subprocess.Popen(  # noqa: S603 - argv is validated, never shell=True
                argv,
                cwd=str(self.project_root),
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=subprocess.STDOUT,
                close_fds=True,
                **creation_kwargs,
            )
        except OSError as exc:
            handle.close()
            self.proc = None
            self.last_error = f"failed to spawn {argv[0]}: {exc}"
            self.publisher.emit("component_start_failed", name=self.name, error=self.last_error)
            return False

        self._log_handle = handle
        self.last_error = None
        self.publisher.emit(
            "component_started",
            name=self.name,
            pid=self.proc.pid,
            argv=argv,
            log_file=str(log_path),
        )
        return True

    def stop(self) -> bool:
        """Terminate the child's process group. Returns ``True`` if it is gone."""
        proc = self.proc
        if proc is None:
            return True
        if proc.poll() is None:
            self.publisher.emit("component_stopping", name=self.name, pid=proc.pid)
            self._signal_group(signal.SIGTERM)
            try:
                proc.wait(timeout=TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                self.publisher.emit("component_kill", name=self.name, pid=proc.pid)
                self._signal_group(signal.SIGKILL if _POSIX else signal.SIGTERM)
                try:
                    proc.wait(timeout=TERM_GRACE_SECONDS)
                except subprocess.TimeoutExpired:  # pragma: no cover - unkillable child
                    self.publisher.emit("component_stop_failed", name=self.name, pid=proc.pid)
                    return False
        self.publisher.emit("component_stopped", name=self.name, returncode=proc.returncode)
        self._close_log()
        self.proc = None
        return True

    def _signal_group(self, sig: int) -> None:
        """Signal the child's entire process group, falling back to the child."""
        proc = self.proc
        if proc is None:
            return
        try:
            if _POSIX:
                os.killpg(os.getpgid(proc.pid), sig)
            else:  # pragma: no cover - Windows deployments are not the target
                proc.terminate()
        except (ProcessLookupError, PermissionError, OSError):
            with contextlib.suppress(OSError):
                proc.terminate()

    def _close_log(self) -> None:
        if self._log_handle is not None:
            with contextlib.suppress(OSError):
                self._log_handle.close()
            self._log_handle = None


class ProcessSupervisor:
    """Thread-safe registry of :class:`ManagedProcess` instances."""

    def __init__(
        self,
        components: dict[str, ComponentConfig],
        project_root: Path,
        publisher: EventPublisher,
    ) -> None:
        self.project_root = project_root
        self.publisher = publisher
        self._lock = threading.RLock()
        self._processes: dict[str, ManagedProcess] = {
            name: ManagedProcess(name, config, project_root, publisher)
            for name, config in components.items()
        }

    def __contains__(self, name: object) -> bool:
        return name in self._processes

    def names(self) -> list[str]:
        """Return every known component name."""
        return list(self._processes)

    def get(self, name: str) -> ManagedProcess | None:
        """Return a managed process by name, or ``None``."""
        return self._processes.get(name)

    def start(self, name: str) -> bool:
        """Start one component."""
        with self._lock:
            process = self._processes.get(name)
            return process.start() if process else False

    def stop(self, name: str) -> bool:
        """Stop one component."""
        with self._lock:
            process = self._processes.get(name)
            return process.stop() if process else False

    def start_autostart(self) -> dict[str, bool]:
        """Start only components marked ``enabled`` *and* ``autostart``."""
        with self._lock:
            results: dict[str, bool] = {}
            for name, process in self._processes.items():
                if process.config.enabled and process.config.autostart:
                    results[name] = process.start()
            return results

    def stop_all(self) -> None:
        """Stop every running component."""
        with self._lock:
            for process in self._processes.values():
                process.stop()

    def status(self) -> dict[str, dict]:
        """Return a status record for every component."""
        with self._lock:
            return {name: process.info() for name, process in self._processes.items()}
