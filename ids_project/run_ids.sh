#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
RUN_DIR="$PROJECT_ROOT/.run"
BACKEND_PID_FILE="$RUN_DIR/backend.pid"
FRONTEND_PID_FILE="$RUN_DIR/frontend.pid"

mkdir -p "$RUN_DIR"

read_pid() {
    local pid_file="$1"

    if [[ -f "$pid_file" ]]; then
        tr -d '[:space:]' < "$pid_file"
    fi
}

pid_is_running() {
    local pid="$1"
    local state

    kill -0 "$pid" 2>/dev/null || return 1
    [[ -r "/proc/$pid/stat" ]] || return 1
    read -r _ _ state _ < "/proc/$pid/stat"
    [[ "$state" != "Z" ]]
}

stop_process_group() {
    local pid_file="$1"
    local name="$2"
    local pid

    pid="$(read_pid "$pid_file")"
    if [[ -z "$pid" ]]; then
        rm -f "$pid_file"
        return
    fi

    if pid_is_running "$pid"; then
        echo "Stopping previous $name (PID $pid)..."
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        pkill -TERM -s "$pid" 2>/dev/null || true
        for _ in {1..8}; do
            pid_is_running "$pid" || break
            sleep 0.25
        done
        if pid_is_running "$pid"; then
            kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        fi
        pkill -KILL -s "$pid" 2>/dev/null || true
    fi

    rm -f "$pid_file"
}

cleanup() {
    stop_process_group "$BACKEND_PID_FILE" "backend"
    stop_process_group "$FRONTEND_PID_FILE" "frontend"
}

start_process() {
    local name="$1"
    local working_dir="$2"
    local pid_file="$3"
    local log_file="$4"
    shift 4

    echo "Starting $name..."
    (
        cd "$working_dir"
        exec setsid bash -c 'echo "$$" > "$1"; shift; exec "$@"' \
            launcher "$pid_file" "$@"
    ) >"$log_file" 2>&1 &
    for _ in {1..20}; do
        [[ -s "$pid_file" ]] && return
        sleep 0.05
    done
    echo "Timed out starting $name; see $log_file." >&2
    return 1
}

trap cleanup EXIT INT TERM

stop_process_group "$BACKEND_PID_FILE" "backend"
stop_process_group "$FRONTEND_PID_FILE" "frontend"

if [[ -x "$BACKEND_DIR/venv/bin/python" ]]; then
    PYTHON="$BACKEND_DIR/venv/bin/python"
else
    PYTHON="python3"
fi

if ! command -v "$PYTHON" >/dev/null 2>&1 && [[ ! -x "$PYTHON" ]]; then
    echo "Python was not found. Create backend/venv or install python3." >&2
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "npm was not found. Install Node.js 18 or newer." >&2
    exit 1
fi

if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    echo "Installing frontend dependencies..."
    (cd "$FRONTEND_DIR" && npm install)
fi

start_process "backend" "$BACKEND_DIR" "$BACKEND_PID_FILE" "$RUN_DIR/backend.log" \
    "$PYTHON" -m uvicorn main:app --host 0.0.0.0 --port 8000
start_process "frontend" "$FRONTEND_DIR" "$FRONTEND_PID_FILE" "$RUN_DIR/frontend.log" \
    npm run dev -- --host 0.0.0.0

echo "Backend:  http://localhost:8000"
echo "Frontend: http://localhost:5173"
echo "Logs:     $RUN_DIR/backend.log and $RUN_DIR/frontend.log"
echo "Press Ctrl-C to stop both services."

wait