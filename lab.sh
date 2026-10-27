#!/usr/bin/env bash
# Host orchestrator for the packet-analysis lab.
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE=podman-compose

usage() {
  cat <<EOF
Usage: ./lab.sh <command>

  up        build images, create labnet, start target + sniffer
  run       run the four activities against the live capture
  capture   up -> run -> stop sniffer (flushes the pcap) -> down
  down      stop and remove containers, keep captures/
  clean     down, then optionally delete captures/*.pcap
EOF
}

require_tools() {
  command -v podman >/dev/null || { echo "podman not found" >&2; exit 1; }
  command -v "$COMPOSE" >/dev/null || { echo "$COMPOSE not found (try: brew install podman-compose)" >&2; exit 1; }
}

ensure_env() {
  [ -f .env ] || { cp .env.example .env; echo "created .env from .env.example"; }
  mkdir -p captures
}

cmd_up() {
  ensure_env
  "$COMPOSE" build
  "$COMPOSE" up -d target sniffer
}

# Note: if the sniffer is not already running, depends_on starts it, and tcpdump overwrites the pcap
cmd_run() {
  ensure_env
  "$COMPOSE" run --rm attacker
}

# tcpdump can lag behind a burst, and packets still queued when it gets SIGTERM are lost.
# Wait until the pcap stops growing before stopping the sniffer.
wait_for_pcap() {
  local file size last=""
  file="captures/$(sed -n 's/^PCAP_FILE=//p' .env)"
  for _ in $(seq 1 30); do
    size=$(wc -c < "$file" 2>/dev/null | tr -d ' ')
    [ "$size" = "$last" ] && return 0
    last=$size
    sleep 2
  done
}

cmd_capture() {
  cmd_up
  local rc=0
  cmd_run || rc=$?
  wait_for_pcap
  # SIGTERM lets tcpdump flush and close the pcap before the containers are removed
  "$COMPOSE" stop -t 10 sniffer || true
  # tcpdump prints its summary on exit: "packets captured" should match "received by filter",
  # and "dropped by kernel" should be 0
  "$COMPOSE" logs sniffer 2>/dev/null | tail -n 3 || true
  "$COMPOSE" down
  if [ "$rc" -eq 0 ]; then
    echo "capture written to captures/$(sed -n 's/^PCAP_FILE=//p' .env)"
  fi
  return "$rc"
}

cmd_down() {
  "$COMPOSE" down
}

cmd_clean() {
  "$COMPOSE" down
  read -r -p "delete captures/*.pcap too? [y/N] " answer || answer=""
  case "$answer" in
    y|Y) rm -f captures/*.pcap; echo "captures cleared" ;;
    *)   echo "captures kept" ;;
  esac
}

case "${1:-}" in
  up|run|capture|down|clean)
    require_tools
    "cmd_$1"
    ;;
  *)
    usage
    exit 1
    ;;
esac
