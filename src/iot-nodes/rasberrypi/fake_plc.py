"""Fake PLC that periodically emits Modbus-like traffic (outbound) to simulate normal devices.
"""
import time
import socket
import logging


log = logging.getLogger("fake_plc")
log.setLevel(logging.INFO)




def simulate_heartbeat(target_host, target_port=5020, interval=10):
while True:
try:
s = socket.create_connection((target_host, target_port), timeout=3)
# send a tiny pulse to show "alive"
s.send(b"HEARTBEAT")
s.close()
log.info("Sent heartbeat to %s:%s", target_host, target_port)
except Exception as e:
log.debug("Heartbeat failed: %s", e)
time.sleep(interval)




if __name__ == "__main__":
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("target", help="Controller or honeypot host")
parser.add_argument("--interval", type=int, default=10)
args = parser.parse_args()
simulate_heartbeat(args.target, interval=args.interval)
