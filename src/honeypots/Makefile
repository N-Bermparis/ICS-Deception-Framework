# honeypots/Makefile

CXX := g++
CXXFLAGS := -O2 -Wall -Wextra -std=c++17

all: modbus_honeypot

modbus_honeypot: modbus_honeypot.cpp
	$(CXX) $(CXXFLAGS) -o modbus_honeypot modbus_honeypot.cpp

clean:
	rm -f modbus_honeypot
