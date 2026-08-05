# src/native/Makefile — builds every native deception service.
#
# Binaries land in $(BUILD_DIR) (default: <repo>/build), which is gitignored:
# compiled artifacts are never committed.

CXX      ?= g++
CXXSTD   ?= -std=c++17
WARNINGS := -Wall -Wextra -Wpedantic
CXXFLAGS ?= -O2 $(CXXSTD) $(WARNINGS)
LDFLAGS  ?= -pthread
CPPFLAGS += -I$(CURDIR)

BUILD_DIR ?= $(CURDIR)/../../build

TARGETS := modbus_honeypot fake_telnet fake_ssh
BINARIES := $(addprefix $(BUILD_DIR)/,$(TARGETS))

HEADERS := common/net_util.h common/decoy.h

.PHONY: all clean

all: $(BINARIES)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%: %.cpp $(HEADERS) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BINARIES)
