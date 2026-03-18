#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$ROOT_DIR"

PORT="${PORT:-21891}"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/data}"
SHARED_DIR="${SHARED_DIR:-$ROOT_DIR/shared}"

echo "Starting cloudsysncd on port ${PORT}..."
echo "Data directory: ${DATA_DIR}"
echo "Shared directory: ${SHARED_DIR}"
echo "Optional public URL with trycloudflare:"
echo "  cloudflared tunnel --url http://127.0.0.1:${PORT}"
echo ""

exec env PORT="$PORT" DATA_DIR="$DATA_DIR" SHARED_DIR="$SHARED_DIR" node server.js
