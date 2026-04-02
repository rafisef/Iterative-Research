#!/usr/bin/env bash
# Start both the FastAPI backend and Vite dev server.
# Usage: ./web/run.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

cleanup() {
    echo ""
    echo "[web] Shutting down..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    echo "[web] Done."
}
trap cleanup EXIT INT TERM

echo "[web] Starting FastAPI backend on http://localhost:8000"
cd "$SCRIPT_DIR/backend"
uvicorn app:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!

echo "[web] Starting Vite frontend on http://localhost:5173"
cd "$SCRIPT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "  Backend:  http://localhost:8000  (API docs: http://localhost:8000/docs)"
echo "  Frontend: http://localhost:5173"
echo ""

wait
