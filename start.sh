#!/bin/bash
set -e

PORT="${PORT:-21891}"

echo "Starting cloudsysncd on port ${PORT}..."
echo "Optional public URL with trycloudflare:"
echo "  cloudflared tunnel --url http://127.0.0.1:${PORT}"
echo ""

node server.js
