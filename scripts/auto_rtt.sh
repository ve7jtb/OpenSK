#!/usr/bin/env bash
set -u

LOG_FILE="/Users/jbradley/.gemini/antigravity/scratch/opensk_rtt.log"
LOCK_FILE="/tmp/opensk_flashing.lock"
PROBE="1366:1061:001050203170"
REPO_DIR="/Users/jbradley/.gemini/antigravity/scratch/OpenSK"
ELF="${REPO_DIR}/third_party/wasefire/target/thumbv7em-none-eabi/release/runner-nordic"
BIN="${REPO_DIR}/third_party/wasefire/.root/bin/probe-rs"

for pid in $(pgrep -f "auto_rtt.sh" 2>/dev/null || true); do
  if [ "$pid" != "$$" ] && [ "$pid" != "$PPID" ]; then
    kill -9 "$pid" 2>/dev/null || true
  fi
done
killall -9 probe-rs JLinkGDBServer JLinkExe 2>/dev/null || true
sleep 1
: > "$LOG_FILE"
echo "[$(date -u +%FT%TZ)] Starting OpenSK RTT logger daemon (pid $$)..." >> "$LOG_FILE"

while true; do
  if [ ! -f "$LOCK_FILE" ] && [ -x "$BIN" ] && [ -f "$ELF" ]; then
    "$BIN" attach --chip nRF52840_xxAA --probe "$PROBE" "$ELF" >> "$LOG_FILE" 2>&1
    exit_code=$?
    echo "[$(date -u +%FT%TZ)] probe-rs session ended (exit code ${exit_code}), reconnecting..." >> "$LOG_FILE"
  fi
  sleep 1
done
