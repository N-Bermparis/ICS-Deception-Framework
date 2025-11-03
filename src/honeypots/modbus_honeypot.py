"""Minimal Modbus honeypot skeleton using pymodbus for demonstration.


Note: This is intentionally simple — for research use you will extend it to
log full interactions and mimic PLC semantics.
"""
from pymodbus.server.sync import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
import logging


logging.basicConfig()
log = logging.getLogger("modbus_honeypot")
log.setLevel(logging.INFO)




def run(host="0.0.0.0", port=5020):
log.info("Starting Modbus honeypot on %s:%s", host, port)


store = ModbusSlaveContext(
di=ModbusSequentialDataBlock(0, [0] * 100),
co=ModbusSequentialDataBlock(0, [0] * 100),
hr=ModbusSequentialDataBlock(0, [0] * 100),
ir=ModbusSequentialDataBlock(0, [0] * 100),
)
context = ModbusServerContext(slaves=store, single=True)


identity = ModbusDeviceIdentification()
identity.VendorName = 'ICS-Deception'
identity.ProductCode = 'HPOT'
identity.VendorUrl = 'https://example.org'


StartTcpServer(context, identity=identity, address=(host, port))




if __name__ == "__main__":
run()
