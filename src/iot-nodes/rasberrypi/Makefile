# iot-nodes/raspberrypi/Makefile

CXX := g++
CXXFLAGS := -O2 -Wall -Wextra -std=c++17

all: fake_telnet fake_ssh

fake_telnet: fake_telnet.cpp
	$(CXX) $(CXXFLAGS) -o fake_telnet fake_telnet.cpp

fake_ssh: fake_ssh.cpp
	$(CXX) $(CXXFLAGS) -o fake_ssh fake_ssh.cpp

clean:
	rm -f fake_telnet fake_ssh
