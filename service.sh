#!/bin/sh
set -eu

# ── cloudsysncd launchd service manager ──
# Usage: ./service.sh {install|uninstall|start|stop|restart|status|logs}

LABEL="com.cloudsysncd"
ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
PLIST_GEN="$ROOT_DIR/com.cloudsysncd.plist"
PLIST_DST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$ROOT_DIR/logs"

info()  { printf '  %s\n' "$*"; }
ok()    { printf '  ✓ %s\n' "$*"; }
fail()  { printf '  ✗ %s\n' "$*" >&2; }

is_loaded() {
  launchctl list 2>/dev/null | grep -q "$LABEL"
}

detect_node() {
  if command -v node >/dev/null 2>&1; then
    command -v node
  else
    fail "node not found in PATH"
    exit 1
  fi
}

generate_plist() {
  NODE_BIN=$(detect_node)
  PORT="${PORT:-21891}"
  DATA_DIR="${DATA_DIR:-$ROOT_DIR/data}"
  SHARED_DIR="${SHARED_DIR:-$ROOT_DIR/shared}"

  cat > "$PLIST_GEN" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>

  <key>ProgramArguments</key>
  <array>
    <string>$NODE_BIN</string>
    <string>$ROOT_DIR/server.js</string>
  </array>

  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>

  <key>EnvironmentVariables</key>
  <dict>
    <key>PORT</key>
    <string>$PORT</string>
    <key>DATA_DIR</key>
    <string>$DATA_DIR</string>
    <key>SHARED_DIR</key>
    <string>$SHARED_DIR</string>
    <key>NODE_ENV</key>
    <string>production</string>
  </dict>

  <!-- Start at login -->
  <key>RunAtLoad</key>
  <true/>

  <!-- Restart on crash (but not on clean exit) -->
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>

  <!-- Wait 5s before restarting after crash -->
  <key>ThrottleInterval</key>
  <integer>5</integer>

  <!-- Logs -->
  <key>StandardOutPath</key>
  <string>$LOG_DIR/launchd-stdout.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/launchd-stderr.log</string>
</dict>
</plist>
EOF
  ok "Generated plist (node: $NODE_BIN, port: $PORT)"
}

cmd_install() {
  echo "Installing $LABEL ..."

  mkdir -p "$LOG_DIR"
  ok "Log directory: $LOG_DIR"

  generate_plist

  # Copy (not symlink) so the plist is self-contained
  cp -f "$PLIST_GEN" "$PLIST_DST"
  ok "Installed plist -> $PLIST_DST"

  # Load (start) the service
  if is_loaded; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
  fi
  launchctl load -w "$PLIST_DST"
  ok "Service loaded and started"

  sleep 1
  cmd_status
}

cmd_uninstall() {
  echo "Uninstalling $LABEL ..."

  if is_loaded; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    ok "Service unloaded"
  else
    info "Service was not loaded"
  fi

  if [ -L "$PLIST_DST" ] || [ -f "$PLIST_DST" ]; then
    rm -f "$PLIST_DST"
    ok "Removed $PLIST_DST"
  fi

  # Clean up generated local plist
  rm -f "$PLIST_GEN"

  echo "Done. Log files in $LOG_DIR are preserved."
}

cmd_start() {
  if ! [ -f "$PLIST_DST" ]; then
    fail "Service not installed. Run: ./service.sh install"
    exit 1
  fi
  if is_loaded; then
    info "Service is already running"
  else
    launchctl load -w "$PLIST_DST"
    ok "Service started"
  fi
}

cmd_stop() {
  if is_loaded; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    ok "Service stopped"
  else
    info "Service is not running"
  fi
}

cmd_restart() {
  echo "Restarting $LABEL ..."
  cmd_stop
  sleep 1
  cmd_start
}

cmd_status() {
  echo "Service: $LABEL"
  if is_loaded; then
    pid=$(launchctl list | grep "$LABEL" | awk '{print $1}')
    if [ "$pid" != "-" ] && [ -n "$pid" ]; then
      ok "Running (PID $pid)"
    else
      fail "Loaded but not running (check logs)"
    fi
  else
    info "Not loaded"
  fi

  # Quick health check
  PORT=$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:PORT" "$PLIST_DST" 2>/dev/null || echo "21891")
  if curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    ok "Health check passed (port $PORT)"
  else
    info "Health check failed or service not ready (port $PORT)"
  fi
}

cmd_logs() {
  echo "=== stdout (last 30 lines) ==="
  tail -30 "$LOG_DIR/launchd-stdout.log" 2>/dev/null || info "(no stdout log yet)"
  echo ""
  echo "=== stderr (last 30 lines) ==="
  tail -30 "$LOG_DIR/launchd-stderr.log" 2>/dev/null || info "(no stderr log yet)"
  echo ""
  echo "For live tailing:"
  echo "  tail -f $LOG_DIR/launchd-stdout.log $LOG_DIR/launchd-stderr.log"
}

case "${1:-help}" in
  install)    cmd_install ;;
  uninstall)  cmd_uninstall ;;
  start)      cmd_start ;;
  stop)       cmd_stop ;;
  restart)    cmd_restart ;;
  status)     cmd_status ;;
  logs)       cmd_logs ;;
  *)
    echo "Usage: $0 {install|uninstall|start|stop|restart|status|logs}"
    echo ""
    echo "Commands:"
    echo "  install     Generate plist, copy to ~/Library/LaunchAgents, and start"
    echo "  uninstall   Stop service and remove plist"
    echo "  start       Start the service"
    echo "  stop        Stop the service"
    echo "  restart     Stop then start"
    echo "  status      Show running state and health check"
    echo "  logs        Show recent log output"
    echo ""
    echo "Environment overrides (for install):"
    echo "  PORT=8080 ./service.sh install"
    echo "  DATA_DIR=/path/to/data SHARED_DIR=/path/to/shared ./service.sh install"
    exit 1
    ;;
esac
