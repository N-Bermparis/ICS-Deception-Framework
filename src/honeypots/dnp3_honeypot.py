"""DNP3 honeypot placeholder.


For real DNP3 emulation consider the `pydnp3` bindings or a lightweight C++ binary.
"""
import logging
import socket


log = logging.getLogger("dnp3_honeypot")
log.setLevel(logging.INFO)




def run(host="0.0.0.0", port=20000):
log.info("Starting simple TCP DNP3-listener on %s:%s", host, port)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
try:
while True:
conn, addr = s.accept()
log.info("Connection from %s", addr)
data = conn.recv(2048)
log.info("Received %d bytes", len(data))
# naive response for research scaffold
conn.send(b"\x05\x64")
conn.close()
except KeyboardInterrupt:
s.close()




if __name__ == "__main__":
run()
