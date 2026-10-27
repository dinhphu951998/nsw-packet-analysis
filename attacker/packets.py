#!/usr/bin/env python3
# Scapy fallback for the hping3 steps in run-activities.sh.
#   packets.py odd TARGET PORT COUNT         crafted SYN+FIN and FIN+PSH+URG packets
#   packets.py syn TARGET PORT COUNT RATE    bounded SYN flood from one source address
import argparse
import random
import time

from scapy.all import IP, TCP, conf, send

conf.verb = 0


def odd(target, port, count):
    for flags in ("SF", "FPU"):
        pkts = [
            IP(dst=target) / TCP(dport=port, sport=random.randint(1024, 65535), flags=flags)
            for _ in range(count)
        ]
        send(pkts)


def syn(target, port, count, rate):
    sock = conf.L3socket()
    start = time.monotonic()
    for i in range(count):
        sock.send(IP(dst=target) / TCP(dport=port, sport=random.randint(1024, 65535), flags="S"))
        # pace against the start time, so per-packet overhead does not lower the average rate
        delay = (i + 1) / rate - (time.monotonic() - start)
        if delay > 0:
            time.sleep(delay)
    sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)

    odd_p = sub.add_parser("odd")
    odd_p.add_argument("target")
    odd_p.add_argument("port", type=int)
    odd_p.add_argument("count", type=int)

    syn_p = sub.add_parser("syn")
    syn_p.add_argument("target")
    syn_p.add_argument("port", type=int)
    syn_p.add_argument("count", type=int)
    syn_p.add_argument("rate", type=float)

    args = parser.parse_args()
    if args.mode == "odd":
        odd(args.target, args.port, args.count)
    else:
        syn(args.target, args.port, args.count, args.rate)


if __name__ == "__main__":
    main()
