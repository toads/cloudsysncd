#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$ROOT_DIR"

PORT="${PORT:-21891}"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/data}"
SHARED_DIR="${SHARED_DIR:-$ROOT_DIR/shared}"
MODE="prod"
WITH_CLOUDFLARE=0

usage() {
  cat <<EOF
Usage: ./start.sh [options]

Options:
  --port <port>          Override listen port (default: 21891)
  --data-dir <dir>       Override runtime data directory
  --shared-dir <dir>     Override shared files directory
  --dev                  Start with nodemon for local development
  --cloudflare           Start cloudflared tunnel alongside the server
  -h, --help             Show this help message

Examples:
  ./start.sh
  ./start.sh --port 22991 --data-dir ./.local/data --shared-dir ./.local/shared
  ./start.sh --dev
  ./start.sh --cloudflare
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --port)
      [ "$#" -ge 2 ] || { echo "Missing value for --port" >&2; exit 1; }
      PORT="$2"
      shift 2
      ;;
    --data-dir)
      [ "$#" -ge 2 ] || { echo "Missing value for --data-dir" >&2; exit 1; }
      DATA_DIR="$2"
      shift 2
      ;;
    --shared-dir)
      [ "$#" -ge 2 ] || { echo "Missing value for --shared-dir" >&2; exit 1; }
      SHARED_DIR="$2"
      shift 2
      ;;
    --dev)
      MODE="dev"
      shift
      ;;
    --cloudflare)
      WITH_CLOUDFLARE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "$DATA_DIR" in
  /*) ;;
  *) DATA_DIR="$ROOT_DIR/$DATA_DIR" ;;
esac

case "$SHARED_DIR" in
  /*) ;;
  *) SHARED_DIR="$ROOT_DIR/$SHARED_DIR" ;;
esac

mkdir -p "$DATA_DIR" "$SHARED_DIR"

server_pid=""
cloudflare_pid=""

stop_processes() {
  if [ -n "$cloudflare_pid" ]; then
    kill "$cloudflare_pid" 2>/dev/null || true
    wait "$cloudflare_pid" 2>/dev/null || true
    cloudflare_pid=""
  fi

  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
}

handle_signal() {
  trap - INT TERM
  stop_processes
  exit 130
}

trap handle_signal INT TERM
trap 'stop_processes' EXIT

echo "Starting cloudsysncd..."
echo "Mode: ${MODE}"
echo "Port: ${PORT}"
echo "Data directory: ${DATA_DIR}"
echo "Shared directory: ${SHARED_DIR}"

if [ "$WITH_CLOUDFLARE" -eq 1 ]; then
  if ! command -v cloudflared >/dev/null 2>&1; then
    echo "cloudflared is not installed. Install it first or run without --cloudflare." >&2
    exit 1
  fi
  echo "Cloudflare tunnel: enabled"
  echo "  cloudflared tunnel --url http://127.0.0.1:${PORT}"
else
  echo "Optional public URL with trycloudflare:"
  echo "  cloudflared tunnel --url http://127.0.0.1:${PORT}"
fi
echo ""

if [ "$MODE" = "dev" ]; then
  NODEMON_BIN="$ROOT_DIR/node_modules/.bin/nodemon"
  if [ ! -x "$NODEMON_BIN" ]; then
    echo "nodemon is not installed. Run npm install first." >&2
    exit 1
  fi
  env PORT="$PORT" DATA_DIR="$DATA_DIR" SHARED_DIR="$SHARED_DIR" \
    "$NODEMON_BIN" --watch server.js --watch public server.js &
else
  env PORT="$PORT" DATA_DIR="$DATA_DIR" SHARED_DIR="$SHARED_DIR" node server.js &
fi
server_pid=$!

if [ "$WITH_CLOUDFLARE" -eq 1 ]; then
  cloudflared tunnel --url "http://127.0.0.1:${PORT}" &
  cloudflare_pid=$!
fi

wait "$server_pid"
