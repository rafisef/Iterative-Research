from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import requests

from .io_utils import logger


def start_snippet_server(snippet_path: str, port: int) -> subprocess.Popen:
  """
  Start a Python process running the given snippet file on the specified port.

  The snippet is expected to accept a `--port` argument or define a default.
  """
  script = Path(snippet_path)
  if not script.exists():
    raise FileNotFoundError(f"Snippet file does not exist: {script}")

  logger.info("Starting server for %s on port %d", script, port)
  proc = subprocess.Popen(
    [sys.executable, str(script), "--port", str(port)],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
  )
  return proc


def wait_for_healthcheck(host: str, port: int, timeout_seconds: int) -> bool:
  """
  Poll the /health endpoint until it returns 200 or timeout is reached.
  """
  url = f"http://{host}:{port}/health"
  logger.info("Waiting for health check at %s (timeout=%ss)", url, timeout_seconds)
  deadline = time.time() + timeout_seconds
  while time.time() < deadline:
    try:
      resp = requests.get(url, timeout=3)
      if resp.status_code == 200:
        logger.info("Health check succeeded for %s", url)
        return True
    except Exception:
      time.sleep(1)
      continue
    time.sleep(1)
  logger.warning("Health check failed for %s after %s seconds", url, timeout_seconds)
  return False


def stop_server(proc: Optional[subprocess.Popen]) -> None:
  """
  Ensure the snippet server process is stopped and reaped so that ports are
  freed and no background processes are left running.
  """
  if proc is None:
    return

  try:
    # If the process has already exited, reap it and return.
    if proc.poll() is not None:
      try:
        proc.communicate(timeout=0.1)
      except Exception:
        pass
      logger.info("Server process pid=%s already exited with code %s", proc.pid, proc.returncode)
      return

    logger.info("Terminating server process pid=%s", proc.pid)
    proc.terminate()
    try:
      proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
      logger.warning("Killing unresponsive server process pid=%s", proc.pid)
      proc.kill()
      proc.wait(timeout=5)

    # Drain any remaining output to fully reap the process and close pipes.
    try:
      proc.communicate(timeout=0.1)
    except Exception:
      pass

    logger.info("Server process pid=%s stopped with code %s", proc.pid, proc.returncode)
  except Exception as exc:  # pragma: no cover - defensive
    logger.error("Error stopping server process: %s", exc)

