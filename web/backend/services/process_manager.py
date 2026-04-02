"""
Subprocess lifecycle management for long-running framework operations.

Spawns CLI commands as subprocesses, captures stdout/stderr in real time,
tracks PIDs, and broadcasts log lines to WebSocket clients.
"""
from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

_PYTHON = sys.executable


@dataclass
class ProcessInfo:
    pid: int
    run_id: str
    command: str
    started_at: float = field(default_factory=time.time)
    status: str = "running"
    exit_code: Optional[int] = None
    log_lines: List[str] = field(default_factory=list)
    _proc: Optional[subprocess.Popen] = field(default=None, repr=False)


class ProcessManager:
    """Singleton that tracks all active and recent subprocesses."""

    def __init__(self) -> None:
        self._processes: Dict[int, ProcessInfo] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._lock = threading.Lock()

    def spawn(
        self,
        run_id: str,
        cmd_args: List[str],
        *,
        on_exit: Optional[Callable[[ProcessInfo], None]] = None,
    ) -> ProcessInfo:
        """
        Start a subprocess and begin capturing output.

        Parameters
        ----------
        run_id:   Logical run identifier for WebSocket routing.
        cmd_args: Command + arguments (e.g. ["python", "utils/generate.py", ...]).
        on_exit:  Optional callback invoked (in a thread) when the process exits.

        Returns
        -------
        ProcessInfo with the PID populated.
        """
        proc = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(_REPO_ROOT),
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )

        info = ProcessInfo(
            pid=proc.pid,
            run_id=run_id,
            command=" ".join(cmd_args),
            _proc=proc,
        )

        with self._lock:
            self._processes[proc.pid] = info

        reader = threading.Thread(
            target=self._read_output,
            args=(info, on_exit),
            daemon=True,
        )
        reader.start()
        return info

    def kill(self, pid: int) -> bool:
        """Send SIGTERM to a process. Returns True if signal was sent."""
        with self._lock:
            info = self._processes.get(pid)
        if info is None or info._proc is None:
            return False
        try:
            os.kill(pid, signal.SIGTERM)
            info.status = "cancelled"
            return True
        except ProcessLookupError:
            return False

    def get(self, pid: int) -> Optional[ProcessInfo]:
        with self._lock:
            return self._processes.get(pid)

    def active(self) -> List[ProcessInfo]:
        with self._lock:
            return [p for p in self._processes.values() if p.status == "running"]

    def all_processes(self) -> List[ProcessInfo]:
        with self._lock:
            return list(self._processes.values())

    def subscribe(self, run_id: str) -> asyncio.Queue:
        """Return an asyncio.Queue that receives log lines for this run_id."""
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._subscribers.setdefault(run_id, []).append(q)
        return q

    def unsubscribe(self, run_id: str, q: asyncio.Queue) -> None:
        with self._lock:
            subs = self._subscribers.get(run_id, [])
            if q in subs:
                subs.remove(q)

    def _read_output(
        self,
        info: ProcessInfo,
        on_exit: Optional[Callable[[ProcessInfo], None]],
    ) -> None:
        proc = info._proc
        assert proc is not None and proc.stdout is not None
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                info.log_lines.append(line)
                self._broadcast(info.run_id, line)
        except Exception:
            pass
        finally:
            proc.wait()
            info.exit_code = proc.returncode
            if info.status == "running":
                info.status = "complete" if proc.returncode == 0 else "failed"
            self._broadcast(
                info.run_id,
                f"[process] exited with code {proc.returncode}",
            )
            if on_exit:
                try:
                    on_exit(info)
                except Exception:
                    pass

    def _broadcast(self, run_id: str, line: str) -> None:
        with self._lock:
            queues = list(self._subscribers.get(run_id, []))
        for q in queues:
            try:
                q.put_nowait(line)
            except asyncio.QueueFull:
                pass


process_manager = ProcessManager()
