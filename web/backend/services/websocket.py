"""WebSocket log broadcasting for real-time process output streaming."""
from __future__ import annotations

import asyncio
import json

from fastapi import WebSocket, WebSocketDisconnect

from .process_manager import process_manager


async def log_stream(websocket: WebSocket, run_id: str) -> None:
    """
    Accept a WebSocket connection and stream log lines for the given run_id.

    Lines are sent as JSON: {"type": "log", "line": "...", "run_id": "..."}.
    A final {"type": "close"} message is sent when the process exits (if the
    client is still connected).
    """
    await websocket.accept()

    queue = process_manager.subscribe(run_id)

    # Send buffered lines that arrived before the client connected.
    active = process_manager.active()
    matching = [p for p in process_manager.all_processes() if p.run_id == run_id]
    for p in matching:
        for line in p.log_lines:
            try:
                await websocket.send_json({"type": "log", "line": line, "run_id": run_id})
            except Exception:
                process_manager.unsubscribe(run_id, queue)
                return

    try:
        while True:
            try:
                line = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue

            if line.startswith("[process] exited"):
                await websocket.send_json({"type": "log", "line": line, "run_id": run_id})
                await websocket.send_json({"type": "close", "run_id": run_id})
                break

            await websocket.send_json({"type": "log", "line": line, "run_id": run_id})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        process_manager.unsubscribe(run_id, queue)
