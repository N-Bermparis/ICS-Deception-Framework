#!/usr/bin/env python3
"""
honeypots/dnp3_honeypot.py

Very lightweight DNP3-like TCP honeypot on port 20000.
This is NOT a full DNP3 implementation; it only:
  - Listens on TCP 20000
  - Accepts connections
  - Logs incoming data and replies with static DNP3-ish frames
"""

import os
import socket
import threading
import time

from common.events import EventPublisher

publisher = EventPublisher(source="dnp3_honeypot")

HOST = "0.0.0.0"
PORT = 20000
BANNER = b"\x05\x64\x05\xc4"  # Random DNP3-ish header bytes


def handle_client(conn: socket.socket, addr):
    publisher.info("dnp3_connection", client=f"{addr[0]}:{addr[1]}")
    conn.settimeout(10.0)
    try:
        # Send something that looks like a DNP3 link-layer ACK-ish
        conn.sendall(BANNER + b"\x01\x02\x03\x04")

        while True:
            data = conn.recv(1024)
            if not data:
                break
            publisher.emit(
                "dnp3_request",
                client_ip=addr[0],
                client_port=addr[1],
                length=len(data),
                hex=data.hex(),
            )
            # Echo back with a slight modification
            time.sleep(0.1)
            reply = BANNER + data[:8]
            conn.sendall(reply)
    except socket.timeout:
        publisher.info("dnp3_timeout", client=f"{addr[0]}:{addr[1]}")
    except Exception as e:
        publisher.error("dnp3_error", error=str(e), client=f"{addr[0]}:{addr[1]}")
    finally:
        conn.close()
        publisher.info("dnp3_connection_closed", client=f"{addr[0]}:{addr[1]}")


def main():
    publisher.info("dnp3_honeypot_startup", host=HOST, port=PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
