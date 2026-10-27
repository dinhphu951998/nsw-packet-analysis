#!/bin/sh
# Runs the four lab activities against the target, in order.
# Every value comes from .env (passed in through env_file), so set -u fails fast on a missing key.
set -u

HELPER=/opt/attacker/packets.py

log()    { printf '[%s] %s\n' "$(date +%T)" "$*"; }
banner() { printf '\n========== %s ==========\n' "$*"; }
csv()    { echo "$1" | tr ',' ' '; }

wait_for_target() {
  log "waiting for http://$TARGET_IP/"
  tries=0
  until curl -s -o /dev/null --max-time 2 "http://$TARGET_IP/"; do
    tries=$((tries + 1))
    if [ "$tries" -ge 30 ]; then
      log "target never answered"
      exit 1
    fi
    sleep 1
  done
  log "target is up"
}

# Activity 1: nmap host discovery, then a TCP SYN scan of SCAN_PORTS
scan() {
  banner "1/4 network scanning: ping sweep + TCP SYN scan"
  nmap -n -sn "$TARGET_IP"
  nmap -n -sS -p "$SCAN_PORTS" -T"$SCAN_TIMING" "$TARGET_IP"
}

# Activity 2: fixed-interval HTTP callbacks to one path (C2-style beacon)
beacon() {
  banner "2/4 anomalous communication: beacon to $BEACON_PATH every ${BEACON_INTERVAL}s"
  for n in $(seq 1 "$BEACON_COUNT"); do
    log "beacon $n/$BEACON_COUNT"
    curl -s -o /dev/null "http://$TARGET_IP$BEACON_PATH"
    sleep "$BEACON_INTERVAL"
  done
}

# Activity 3: random payloads on odd ports, plus crafted TCP flag combinations
unusual() {
  banner "3/4 unusual traffic: odd ports, oversized payloads, crafted packets"
  # UDP, because nothing listens on the odd ports: a TCP connect would be refused before any payload is sent
  for port in $(csv "$ODD_PORTS"); do
    log "UDP datagram of $ODD_PAYLOAD_SIZE bytes to port $port"
    head -c "$ODD_PAYLOAD_SIZE" /dev/urandom | nc -u -w 2 "$TARGET_IP" "$port" || true
  done
  for port in $(csv "$ODD_PORTS"); do
    log "crafted packets to port $port: SYN+FIN, then FIN+PSH+URG"
    if command -v hping3 >/dev/null 2>&1; then
      hping3 -q -c "$CRAFTED_PACKETS" -p "$port" -S -F "$TARGET_IP" || true
      hping3 -q -c "$CRAFTED_PACKETS" -p "$port" -F -P -U "$TARGET_IP" || true
    else
      python3 "$HELPER" odd "$TARGET_IP" "$port" "$CRAFTED_PACKETS"
    fi
  done
}

# Activity 4: bounded SYN flood and HTTP request flood. Runs last so its volume does not hide the earlier activities.
flood() {
  banner "4/4 denial of service (bounded): SYN flood + HTTP flood"
  log "SYN flood: $DOS_SYN_COUNT packets to port $DOS_TARGET_PORT at ${DOS_SYN_RATE}/s"
  if command -v hping3 >/dev/null 2>&1; then
    interval_us=$((1000000 / DOS_SYN_RATE))
    hping3 -q -S -p "$DOS_TARGET_PORT" -c "$DOS_SYN_COUNT" -i "u$interval_us" "$TARGET_IP" || true
  else
    python3 "$HELPER" syn "$TARGET_IP" "$DOS_TARGET_PORT" "$DOS_SYN_COUNT" "$DOS_SYN_RATE"
  fi
  log "HTTP flood: $DOS_HTTP_REQUESTS requests, $DOS_HTTP_CONCURRENCY concurrent"
  ab -q -n "$DOS_HTTP_REQUESTS" -c "$DOS_HTTP_CONCURRENCY" "http://$TARGET_IP/" || true
}

wait_for_target
log "settling ${SETTLE_SECONDS}s so tcpdump is recording"
sleep "$SETTLE_SECONDS"
scan
beacon
unusual
flood
banner "done: all four activities finished"
