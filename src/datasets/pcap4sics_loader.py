#!/usr/bin/env python3
"""
datasets/pcap4sics_loader.py

PCAP loader for pcap4sics and similar datasets.
- Extract Modbus/TCP (port 502) and DNP3 (port 20000) features.
- Optionally replay requests against local honeypots.
- Emit events via common/events.py.
"""

import argparse
import os
import socket
from typing import Optional

from scapy.all import rdpcap, TCP, Raw  # type: ignore

from common.events import EventPublisher

publisher = EventPublisher(source="pcap4sics_loader")

MODBUS_PORT = 502
DNP3_PORT = 20000


def parse_modbus(packet) -> Optional[dict]:
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    tcp = packet[TCP]
    if tcp.dport != MODBUS_PORT and tcp.sport != MODBUS_PORT:
        return None
    payload = bytes(packet[Raw].load)
    if len(payload) < 8:
        return None

    # MBAP header
    trans_id = int.from_bytes(payload[0:2], "big")
    proto_id = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:6], "big")
    unit_id = payload[6]
    if len(payload) < 7 + 1:
        return None

    func_code = payload[7]
    pdu = payload[7:]
    direction = "cs" if tcp.dport == MODBUS_PORT else "sc"
    return {
        "trans_id": trans_id,
        "proto_id": proto_id,
        "length": length,
        "unit_id": unit_id,
        "func_code": func_code,
        "pdu_len": len(pdu),
        "src": f"{packet[0][1].src}:{tcp.sport}",
        "dst": f"{packet[0][1].dst}:{tcp.dport}",
        "direction": direction,
    }


def parse_dnp3(packet) -> Optional[dict]:
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    tcp = packet[TCP]
    if tcp.dport != DNP3_PORT and tcp.sport != DNP3_PORT:
        return None
    payload = bytes(packet[Raw].load)
    if len(payload) < 2:
        return None
    direction = "cs" if tcp.dport == DNP3_PORT else "sc"
    return {
        "len": len(payload),
        "src": f"{packet[0][1].src}:{tcp.sport}",
        "dst": f"{packet[0][1].dst}:{tcp.dport}",
        "direction": direction,
        "hex_sample": payload[:16].hex(),
    }


def replay_modbus(packet, target_host="127.0.0.1", target_port=502):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return
    tcp = packet[TCP]
    if tcp.dport != MODBUS_PORT:
        return
    payload = bytes(packet[Raw].load)
    try:
        with socket.create_connection((target_host, target_port), timeout=2.0) as s:
            s.sendall(payload)
            _ = s.recv(1024)
    except Exception as e:
        publisher.error("modbus_replay_error", error=str(e))


def replay_dnp3(packet, target_host="127.0.0.1", target_port=20000):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return
    tcp = packet[TCP]
    if tcp.dport != DNP3_PORT:
        return
    payload = bytes(packet[Raw].load)
    try:
        with socket.create_connection((target_host, target_port), timeout=2.0) as s:
            s.sendall(payload)
            _ = s.recv(1024)
    except Exception as e:
        publisher.error("dnp3_replay_error", error=str(e))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--replay", action="store_true", help="Replay traffic to honeypots")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        raise SystemExit(f"PCAP not found: {args.pcap}")

    packets = rdpcap(args.pcap)
    publisher.info("pcap_loaded", pcap=args.pcap, count=len(packets))

    for pkt in packets:
        md = parse_modbus(pkt)
        if md:
            publisher.emit("modbus_packet", **md)
            if args.replay:
                replay_modbus(pkt)
            continue
        dn = parse_dnp3(pkt)
        if dn:
            publisher.emit("dnp3_packet", **dn)
            if args.replay:
                replay_dnp3(pkt)


if __name__ == "__main__":
    main()

