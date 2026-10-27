# Implementation Plan — Security Activity Traffic Generator for PCAP Analysis

## 1. Goal

Build a self-contained, Podman-based lab that generates three categories of
security-relevant network traffic against a controlled target and captures the
whole run into a single pcap for later analysis in a network security course.

Activities to simulate (confirmed scope):

| # | Category | Technique | PCAP signature to study |
|---|----------|-----------|--------------------------|
| 1 | Network scanning | nmap ping sweep + TCP SYN port scan | Many SYNs to sequential ports, RST/SYN-ACK replies, no full handshake |
| 2 | Anomalous communication pattern | Fixed-interval HTTP "beacon" callbacks (C2-style) | Regular, low-jitter requests to one path at a constant period |
| 3 | Unusual network traffic | Connections to non-standard ports + oversized/odd payloads + crafted packets | Traffic on odd ports (4444/31337/…), abnormal packet sizes, protocol deviations |
| 4 | Denial of Service (DoS) | Bounded SYN flood + HTTP request flood against the lab target | High-rate SYNs from one source, half-open connections, burst of HTTP requests with no normal pacing |

Everything runs on an isolated private bridge network — no traffic leaves the
host, nothing targets anything outside the lab.

## 2. Topology (Attacker + Target + Sniffer)

Three containers on one dedicated Podman bridge network (`labnet`), with static IPs
from `.env`:

```
          labnet  (e.g. 172.28.0.0/24)
  ┌────────────────────────────────────────────┐
  │                                             │
  │  attacker ──────generates traffic──────▶ target (nginx)
  │  172.28.0.20                             172.28.0.10
  │                                             ▲
  │                                   shares netns│
  │                                      sniffer (tcpdump)
  │                                   writes → ./captures/combined.pcap
  └────────────────────────────────────────────┘
```

**Key design point — how the sniffer sees the traffic.**
On a Podman bridge network, unicast traffic between two containers is *switched*,
so a third container on the same bridge would **not** see attacker↔target packets.
The sniffer therefore **shares the target's network namespace**
(`network_mode: "service:target"`) and runs `tcpdump` on the target's `eth0`.
Because all three activities are aimed at the target, capturing at the target NIC
records 100% of the relevant traffic in one combined pcap.

| Container | Base image | Role |
|-----------|-----------|------|
| `target` | `nginx:alpine` | Victim service; serves `/` and `/heartbeat`; owns the network namespace |
| `sniffer` | `alpine` + `tcpdump` | Shares `target` netns; captures combined pcap to a mounted volume |
| `attacker` | `alpine` + `nmap`, `hping3`, `curl` (fallback `python3`/scapy) | Runs the three activities in sequence |

## 3. Files to create

```
packet-analysis/
├── .env                      # all tunable config (IPs, ports, timings)
├── .env.example              # committed template (same keys, safe defaults)
├── podman-compose.yml        # 3 services + labnet definition
├── lab.sh                    # host orchestrator: up / run / down / clean
├── attacker/
│   ├── Containerfile         # alpine + nmap + hping3 + curl + python3/scapy
│   └── run-activities.sh     # the core script: runs the 3 activities
├── sniffer/
│   └── Containerfile         # alpine + tcpdump (or run inline via image cmd)
├── www/
│   ├── index.html            # "Hello from Docker" (recreated target page)
│   └── heartbeat             # "Heartbeat response" (beacon endpoint)
└── captures/                 # bind-mounted; combined.pcap lands here
```

## 4. Configuration — `.env`

All behavior tunable without editing code (requirement: easy modification).

```dotenv
# --- network ---
LAB_SUBNET=172.28.0.0/24
LAB_GATEWAY=172.28.0.1
TARGET_IP=172.28.0.10
ATTACKER_IP=172.28.0.20

# --- capture ---
PCAP_FILE=combined.pcap          # written under captures/
CAPTURE_SNAPLEN=0                # full packets
SETTLE_SECONDS=2                # pause so tcpdump is ready before traffic starts

# --- activity 1: scanning ---
SCAN_PORTS=1-1024
SCAN_TIMING=4                   # nmap -T template

# --- activity 2: beaconing ---
BEACON_PATH=/heartbeat
BEACON_INTERVAL=5              # seconds between callbacks
BEACON_COUNT=20               # number of callbacks

# --- activity 3: unusual traffic ---
ODD_PORTS=4444,6666,31337
ODD_PAYLOAD_SIZE=2048         # bytes, oversized payload
CRAFTED_PACKETS=10            # count of hping3/scapy crafted packets

# --- activity 4: denial of service (bounded) ---
DOS_SYN_COUNT=2000            # total SYN packets in the flood (hard cap)
DOS_SYN_RATE=500             # packets/sec (keeps the lab responsive)
DOS_TARGET_PORT=80           # port under attack
DOS_HTTP_REQUESTS=1000        # HTTP flood request count
DOS_HTTP_CONCURRENCY=20       # parallel connections for the HTTP flood
```

`.env.example` is committed; `.env` is git-ignored (it's the editable local copy).

## 5. The core script — `attacker/run-activities.sh`

Entrypoint of the attacker container. Pseudo-flow:

1. **Wait for target** — poll `curl $TARGET_IP` until the target answers (or timeout).
2. **Settle** — `sleep $SETTLE_SECONDS` so the already-running sniffer catches the start.
3. **Activity 1 — Scanning**
   - `nmap -sn $TARGET_IP` (host discovery / ping sweep)
   - `nmap -sS -p $SCAN_PORTS -T$SCAN_TIMING $TARGET_IP` (SYN scan)
4. **Activity 2 — Beaconing**
   - Loop `BEACON_COUNT` times: `curl -s $TARGET_IP$BEACON_PATH`, `sleep $BEACON_INTERVAL`
   - Fixed interval → the tell-tale periodic pattern for analysis.
5. **Activity 3 — Unusual traffic**
   - For each port in `ODD_PORTS`: attempt a connection / send `ODD_PAYLOAD_SIZE`-byte payload.
   - Send `CRAFTED_PACKETS` crafted packets via `hping3` (e.g. odd flag combos, large frames); `scapy` fallback if hping3 unavailable.
6. **Activity 4 — Denial of Service (bounded)**
   - SYN flood: `hping3 -S --flood`-style burst to `DOS_TARGET_PORT`, **hard-capped** at `DOS_SYN_COUNT` packets and throttled to `DOS_SYN_RATE` pkt/s (scapy fallback with an explicit send count).
   - HTTP flood: `DOS_HTTP_REQUESTS` requests at `DOS_HTTP_CONCURRENCY` parallelism against `/`.
   - Bounded by count/rate so it produces a clear, analyzable flood signature without wedging the lab host — all traffic stays on `labnet` against the lab's own target.
7. **Done** — print a per-activity summary; exit 0. Exit stops the run so `lab.sh` can tear down and finalize the pcap.

Each activity is clearly separated and logs a banner, so the pcap timeline maps
directly onto activity boundaries during analysis. Activity 4 (DoS) runs **last**
so its high-volume burst doesn't crowd out the quieter signatures of the earlier
activities in the same capture.

## 6. Capture lifecycle

- `sniffer` starts **first** (compose dependency), begins `tcpdump -i eth0 -s $CAPTURE_SNAPLEN -w /captures/$PCAP_FILE`.
- `attacker` starts after `target` is healthy and runs all activities into the live capture.
- When `attacker` exits, `lab.sh` sends the sniffer a clean stop (SIGTERM so tcpdump flushes), then `podman-compose down`.
- Result: one `captures/combined.pcap` containing scan + beacon + unusual traffic back-to-back.

## 7. Host orchestrator — `lab.sh`

Thin wrapper so the whole thing is one command:

| Command | Action |
|---------|--------|
| `./lab.sh up` | build images, create `labnet`, start target + sniffer |
| `./lab.sh run` | run the attacker activities against the live capture |
| `./lab.sh capture` | `up` → `run` → stop sniffer → `down` (the common path) |
| `./lab.sh down` | stop and remove containers, keep the pcap |
| `./lab.sh clean` | `down` + remove `labnet` + optionally clear `captures/` |

## 8. Build order (TDD-ish, verify each layer)

1. `www/` + `target` service → `curl` the target page works.
2. `sniffer` sharing target netns → produces a (tiny) pcap during a manual curl. **Validate the netns-sharing assumption here before building anything else.**
3. `attacker` image builds with nmap/hping3/curl present.
4. Activity 1 only → confirm SYN scan appears in the pcap.
5. Activities 2 and 3 → confirm beacon periodicity and odd-port/oversized traffic.
6. Activity 4 → confirm the DoS flood appears and respects the `DOS_*` caps (lab stays responsive).
7. `lab.sh capture` end-to-end → single combined pcap with all four, verified in Wireshark/tshark.

## 9. Validation checklist

- [ ] `captures/combined.pcap` opens in Wireshark and is non-empty.
- [ ] Activity 1: a burst of SYNs to sequential ports is visible (filter `tcp.flags.syn==1 && tcp.flags.ack==0`).
- [ ] Activity 2: requests to `BEACON_PATH` at a constant `BEACON_INTERVAL` (visible in the time deltas).
- [ ] Activity 3: packets on each `ODD_PORTS` entry and frames near `ODD_PAYLOAD_SIZE`.
- [ ] Activity 4: high-rate SYN burst to `DOS_TARGET_PORT` + HTTP request flood, packet count ≈ `DOS_SYN_COUNT` (filter `tcp.flags.syn==1 && tcp.flags.ack==0`), and the lab host stayed responsive.
- [ ] Changing a value in `.env` (e.g. `SCAN_PORTS`, `BEACON_INTERVAL`) changes the pcap on the next run with no code edits.
- [ ] No traffic on any interface outside `labnet`.

## 10. Assumptions & open points

- **Scope is self-contained & educational** — all targets are the lab's own `target` container; nothing external is touched.
- Assumed `172.28.0.0/24` for `labnet`; change in `.env` if it collides with an existing Podman network.
- `hping3` is the primary crafted-packet tool; if the Alpine package is unavailable in your mirror, the plan falls back to a small `scapy` (python3) script — both paths are kept in `attacker/`.
- Capture is **one combined pcap** (per your choice). If per-activity pcaps are wanted later, the sniffer step can be split with markers instead.
```
