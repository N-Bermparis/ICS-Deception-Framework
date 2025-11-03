"""Simple test that connects to the modbus honeypot and performs a read.
"""
from pymodbus.client.sync import ModbusTcpClient




def test_read():
c = ModbusTcpClient('localhost', port=5020)
assert c.connect()
rr = c.read_holding_registers(0, 2)
print('Registers:', rr.registers)
c.close()




if __name__ == '__main__':
test_read()
