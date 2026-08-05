// modbus_honeypot.cpp — Modbus/TCP deception service.
//
// Emulates a small PLC register file over Modbus/TCP for authorized laboratory
// research. Supported function codes:
//
//   FC01 (0x01) Read Coils
//   FC03 (0x03) Read Holding Registers
//   FC05 (0x05) Write Single Coil
//   FC06 (0x06) Write Single Register
//   FC16 (0x10) Write Multiple Registers
//
// This is a deception sensor, not a certified Modbus device. Diagnostics,
// file-record access, serial-gateway semantics and device identification are
// not implemented; unsupported function codes get an ILLEGAL FUNCTION exception.
//
// Framing: the MBAP length field drives reassembly, so a request split across
// several TCP segments is reconstructed, and several requests arriving in one
// segment are all serviced. Malformed frames are logged and the connection is
// dropped without ever crashing the service.
//
// Defaults are safe: loopback bind, unprivileged port 5020, zero simulated
// latency and zero random error injection (so tests are deterministic).

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
// std::system_error is thrown by std::thread's constructor and caught below.
// libstdc++ happens to pull it in via <thread>, but that is not guaranteed by
// the standard and breaks on other standard libraries, so include it directly.
#include <system_error>
#include <thread>
#include <vector>

#include "common/net_util.h"

namespace {

// -- Modbus constants -------------------------------------------------------

constexpr size_t kMbapHeaderLen = 7;
constexpr uint16_t kModbusProtocolId = 0x0000;
constexpr size_t kMaxPduLen = 253;
constexpr size_t kMaxAduLen = kMbapHeaderLen + kMaxPduLen;  // 260
// MBAP length counts unit id + PDU, so its legal range is 2 .. 254.
constexpr uint16_t kMinMbapLength = 2;
constexpr uint16_t kMaxMbapLength = static_cast<uint16_t>(kMaxPduLen + 1);
// Reassembly buffer ceiling: enough for several pipelined frames, small enough
// that a peer cannot exhaust memory.
constexpr size_t kMaxBuffer = 4 * kMaxAduLen;

constexpr uint8_t kFcReadCoils = 0x01;
constexpr uint8_t kFcReadHoldingRegisters = 0x03;
constexpr uint8_t kFcWriteSingleCoil = 0x05;
constexpr uint8_t kFcWriteSingleRegister = 0x06;
constexpr uint8_t kFcWriteMultipleRegisters = 0x10;

constexpr uint8_t kExcIllegalFunction = 0x01;
constexpr uint8_t kExcIllegalDataAddress = 0x02;
constexpr uint8_t kExcIllegalDataValue = 0x03;
constexpr uint8_t kExcServerDeviceFailure = 0x04;

constexpr size_t kCoilCount = 256;
constexpr size_t kRegisterCount = 256;

// -- Configuration ----------------------------------------------------------

struct Config {
    std::string bind_addr = "127.0.0.1";
    uint16_t port = 5020;
    // Percentage chance of answering with a SERVER DEVICE FAILURE exception.
    // Zero by default: random failures must never make the tests flaky.
    int error_percent = 0;
    long min_latency_ms = 0;
    long max_latency_ms = 0;
    unsigned long seed = 0;
    bool seed_given = false;
    int max_clients = 16;
    int crit_start = 100;
    int crit_end = 110;
    double recv_timeout = 30.0;
    std::string log_path = "runtime/modbus_honeypot.jsonl";
};

// -- Shared state -----------------------------------------------------------

struct PlcState {
    std::mutex mutex;
    bool coils[kCoilCount] = {};
    uint16_t registers[kRegisterCount] = {};
};

PlcState g_state;
std::atomic<int> g_active_clients{0};
std::atomic<bool> g_running{true};

std::mutex g_rng_mutex;
std::mt19937 g_rng;

icsd::JsonLogger *g_log = nullptr;

int random_percent() {
    std::lock_guard<std::mutex> guard(g_rng_mutex);
    std::uniform_int_distribution<int> dist(0, 99);
    return dist(g_rng);
}

long random_latency(long min_ms, long max_ms) {
    if (max_ms <= min_ms) {
        return min_ms;
    }
    std::lock_guard<std::mutex> guard(g_rng_mutex);
    std::uniform_int_distribution<long> dist(min_ms, max_ms);
    return dist(g_rng);
}

// -- Framing helpers --------------------------------------------------------

uint16_t be16(const uint8_t *p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

void put_be16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

// Wrap a PDU in an MBAP header with a correctly computed length field.
std::vector<uint8_t> build_adu(uint16_t transaction_id, uint8_t unit_id,
                               const std::vector<uint8_t> &pdu) {
    std::vector<uint8_t> adu;
    adu.reserve(kMbapHeaderLen + pdu.size());
    put_be16(adu, transaction_id);
    put_be16(adu, kModbusProtocolId);
    put_be16(adu, static_cast<uint16_t>(pdu.size() + 1));  // unit id + PDU
    adu.push_back(unit_id);
    adu.insert(adu.end(), pdu.begin(), pdu.end());
    return adu;
}

// Exact-size (9 byte) exception response. No bytes of the offending request
// are ever copied into the reply.
std::vector<uint8_t> build_exception(uint16_t transaction_id, uint8_t unit_id,
                                     uint8_t function_code, uint8_t exception_code) {
    std::vector<uint8_t> pdu;
    pdu.push_back(static_cast<uint8_t>(function_code | 0x80));
    pdu.push_back(exception_code);
    return build_adu(transaction_id, unit_id, pdu);
}

bool is_critical_register(const Config &cfg, long address) {
    return address >= cfg.crit_start && address <= cfg.crit_end;
}

// -- Function code handlers -------------------------------------------------
//
// Each handler receives the PDU (function code + data) and validates its exact
// length before touching any field.

std::vector<uint8_t> handle_read_coils(uint16_t tid, uint8_t uid,
                                       const std::vector<uint8_t> &pdu) {
    if (pdu.size() != 5) {
        return build_exception(tid, uid, kFcReadCoils, kExcIllegalDataValue);
    }
    uint16_t address = be16(&pdu[1]);
    uint16_t quantity = be16(&pdu[3]);
    if (quantity == 0 || quantity > 2000) {
        return build_exception(tid, uid, kFcReadCoils, kExcIllegalDataValue);
    }
    if (static_cast<size_t>(address) + quantity > kCoilCount) {
        return build_exception(tid, uid, kFcReadCoils, kExcIllegalDataAddress);
    }

    const size_t byte_count = (static_cast<size_t>(quantity) + 7) / 8;
    std::vector<uint8_t> response_pdu;
    response_pdu.reserve(2 + byte_count);
    response_pdu.push_back(kFcReadCoils);
    response_pdu.push_back(static_cast<uint8_t>(byte_count));
    response_pdu.insert(response_pdu.end(), byte_count, 0x00);

    {
        std::lock_guard<std::mutex> guard(g_state.mutex);
        for (uint16_t i = 0; i < quantity; ++i) {
            if (g_state.coils[address + i]) {
                response_pdu[2 + (i / 8)] |= static_cast<uint8_t>(1u << (i % 8));
            }
        }
    }
    return build_adu(tid, uid, response_pdu);
}

std::vector<uint8_t> handle_read_holding_registers(uint16_t tid, uint8_t uid,
                                                   const std::vector<uint8_t> &pdu) {
    if (pdu.size() != 5) {
        return build_exception(tid, uid, kFcReadHoldingRegisters, kExcIllegalDataValue);
    }
    uint16_t address = be16(&pdu[1]);
    uint16_t quantity = be16(&pdu[3]);
    if (quantity == 0 || quantity > 125) {
        return build_exception(tid, uid, kFcReadHoldingRegisters, kExcIllegalDataValue);
    }
    if (static_cast<size_t>(address) + quantity > kRegisterCount) {
        return build_exception(tid, uid, kFcReadHoldingRegisters, kExcIllegalDataAddress);
    }

    std::vector<uint8_t> response_pdu;
    response_pdu.reserve(2 + static_cast<size_t>(quantity) * 2);
    response_pdu.push_back(kFcReadHoldingRegisters);
    response_pdu.push_back(static_cast<uint8_t>(quantity * 2));
    {
        std::lock_guard<std::mutex> guard(g_state.mutex);
        for (uint16_t i = 0; i < quantity; ++i) {
            put_be16(response_pdu, g_state.registers[address + i]);
        }
    }
    return build_adu(tid, uid, response_pdu);
}

std::vector<uint8_t> handle_write_single_coil(const Config &cfg, uint16_t tid, uint8_t uid,
                                              const std::vector<uint8_t> &pdu,
                                              bool &sabotage, long &sabotage_addr) {
    if (pdu.size() != 5) {
        return build_exception(tid, uid, kFcWriteSingleCoil, kExcIllegalDataValue);
    }
    uint16_t address = be16(&pdu[1]);
    uint16_t value = be16(&pdu[3]);
    // Modbus permits exactly two coil values.
    if (value != 0x0000 && value != 0xFF00) {
        return build_exception(tid, uid, kFcWriteSingleCoil, kExcIllegalDataValue);
    }
    if (address >= kCoilCount) {
        return build_exception(tid, uid, kFcWriteSingleCoil, kExcIllegalDataAddress);
    }
    {
        std::lock_guard<std::mutex> guard(g_state.mutex);
        g_state.coils[address] = (value == 0xFF00);
    }
    if (is_critical_register(cfg, address)) {
        sabotage = true;
        sabotage_addr = address;
    }
    return build_adu(tid, uid, pdu);  // a successful write echoes the request PDU
}

std::vector<uint8_t> handle_write_single_register(const Config &cfg, uint16_t tid, uint8_t uid,
                                                  const std::vector<uint8_t> &pdu,
                                                  bool &sabotage, long &sabotage_addr) {
    if (pdu.size() != 5) {
        return build_exception(tid, uid, kFcWriteSingleRegister, kExcIllegalDataValue);
    }
    uint16_t address = be16(&pdu[1]);
    uint16_t value = be16(&pdu[3]);
    if (address >= kRegisterCount) {
        return build_exception(tid, uid, kFcWriteSingleRegister, kExcIllegalDataAddress);
    }
    {
        std::lock_guard<std::mutex> guard(g_state.mutex);
        g_state.registers[address] = value;
    }
    if (is_critical_register(cfg, address)) {
        sabotage = true;
        sabotage_addr = address;
    }
    return build_adu(tid, uid, pdu);
}

std::vector<uint8_t> handle_write_multiple_registers(const Config &cfg, uint16_t tid, uint8_t uid,
                                                     const std::vector<uint8_t> &pdu,
                                                     bool &sabotage, long &sabotage_addr) {
    // fc(1) + addr(2) + qty(2) + byte_count(1) + payload
    if (pdu.size() < 6) {
        return build_exception(tid, uid, kFcWriteMultipleRegisters, kExcIllegalDataValue);
    }
    uint16_t address = be16(&pdu[1]);
    uint16_t quantity = be16(&pdu[3]);
    uint8_t byte_count = pdu[5];
    if (quantity == 0 || quantity > 123 ||
        byte_count != static_cast<uint8_t>(quantity * 2) ||
        pdu.size() != static_cast<size_t>(6) + byte_count) {
        return build_exception(tid, uid, kFcWriteMultipleRegisters, kExcIllegalDataValue);
    }
    if (static_cast<size_t>(address) + quantity > kRegisterCount) {
        return build_exception(tid, uid, kFcWriteMultipleRegisters, kExcIllegalDataAddress);
    }

    {
        std::lock_guard<std::mutex> guard(g_state.mutex);
        for (uint16_t i = 0; i < quantity; ++i) {
            g_state.registers[address + i] = be16(&pdu[6 + 2 * i]);
        }
    }
    for (uint16_t i = 0; i < quantity; ++i) {
        if (is_critical_register(cfg, address + i)) {
            sabotage = true;
            sabotage_addr = address + i;
            break;
        }
    }

    // Response echoes only the starting address and the quantity written.
    std::vector<uint8_t> response_pdu;
    response_pdu.reserve(5);
    response_pdu.push_back(kFcWriteMultipleRegisters);
    put_be16(response_pdu, address);
    put_be16(response_pdu, quantity);
    return build_adu(tid, uid, response_pdu);
}

std::vector<uint8_t> process_pdu(const Config &cfg, uint16_t tid, uint8_t uid,
                                 const std::vector<uint8_t> &pdu, bool &sabotage,
                                 long &sabotage_addr) {
    const uint8_t function_code = pdu[0];

    if (cfg.error_percent > 0 && random_percent() < cfg.error_percent) {
        return build_exception(tid, uid, function_code, kExcServerDeviceFailure);
    }

    switch (function_code) {
        case kFcReadCoils:
            return handle_read_coils(tid, uid, pdu);
        case kFcReadHoldingRegisters:
            return handle_read_holding_registers(tid, uid, pdu);
        case kFcWriteSingleCoil:
            return handle_write_single_coil(cfg, tid, uid, pdu, sabotage, sabotage_addr);
        case kFcWriteSingleRegister:
            return handle_write_single_register(cfg, tid, uid, pdu, sabotage, sabotage_addr);
        case kFcWriteMultipleRegisters:
            return handle_write_multiple_registers(cfg, tid, uid, pdu, sabotage, sabotage_addr);
        default:
            return build_exception(tid, uid, function_code, kExcIllegalFunction);
    }
}

// -- Connection handling ----------------------------------------------------

void log_client_event(const std::string &event_type, const std::string &ip, uint16_t port,
                      const std::vector<std::string> &extra) {
    std::vector<std::string> parts;
    parts.push_back(icsd::jstr("client_ip", ip));
    parts.push_back(icsd::jnum("client_port", port));
    for (const std::string &item : extra) {
        parts.push_back(item);
    }
    g_log->event(event_type, icsd::jjoin(parts));
}

void handle_client(int fd, std::string ip, uint16_t port, Config cfg) {
    icsd::set_recv_timeout(fd, cfg.recv_timeout);
    icsd::set_send_timeout(fd, cfg.recv_timeout);
    log_client_event("connection", ip, port,
                     {icsd::jstr("banner", "RTU-358 Control Module v1.7")});

    std::vector<uint8_t> buffer;
    buffer.reserve(kMaxAduLen);
    uint8_t chunk[1024];
    std::string close_reason = "peer_closed";

    while (g_running.load()) {
        // 1. Drain every complete frame already buffered. This is what makes
        //    pipelined requests in a single segment all get answered.
        bool fatal = false;
        while (buffer.size() >= kMbapHeaderLen) {
            const uint16_t protocol_id = be16(&buffer[2]);
            const uint16_t mbap_length = be16(&buffer[4]);

            if (protocol_id != kModbusProtocolId) {
                log_client_event("modbus_malformed", ip, port,
                                 {icsd::jstr("reason", "bad_protocol_id"),
                                  icsd::jnum("protocol_id", protocol_id)});
                fatal = true;
                close_reason = "malformed_frame";
                break;
            }
            if (mbap_length < kMinMbapLength || mbap_length > kMaxMbapLength) {
                log_client_event("modbus_malformed", ip, port,
                                 {icsd::jstr("reason", "bad_mbap_length"),
                                  icsd::jnum("mbap_length", mbap_length)});
                fatal = true;
                close_reason = "malformed_frame";
                break;
            }

            const size_t frame_len = kMbapHeaderLen - 1 + mbap_length;
            if (buffer.size() < frame_len) {
                break;  // partial frame: wait for the rest of the stream
            }

            const uint16_t transaction_id = be16(&buffer[0]);
            const uint8_t unit_id = buffer[6];
            std::vector<uint8_t> pdu(buffer.begin() + static_cast<long>(kMbapHeaderLen),
                                     buffer.begin() + static_cast<long>(frame_len));
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<long>(frame_len));

            log_client_event("modbus_request", ip, port,
                             {icsd::jnum("unit_id", unit_id),
                              icsd::jnum("function_code", pdu[0]),
                              icsd::jnum("transaction_id", transaction_id),
                              icsd::jnum("bytes_in", static_cast<long long>(frame_len))});

            if (cfg.max_latency_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(
                    random_latency(cfg.min_latency_ms, cfg.max_latency_ms)));
            }

            bool sabotage = false;
            long sabotage_addr = -1;
            std::vector<uint8_t> response =
                process_pdu(cfg, transaction_id, unit_id, pdu, sabotage, sabotage_addr);

            if (!icsd::send_all(fd, response.data(), response.size())) {
                log_client_event("modbus_connection_error", ip, port,
                                 {icsd::jstr("reason", "send_failed"),
                                  icsd::jnum("errno", errno)});
                fatal = true;
                close_reason = "send_failed";
                break;
            }
            log_client_event("modbus_response", ip, port,
                             {icsd::jnum("function_code", response[kMbapHeaderLen]),
                              icsd::jnum("bytes_out", static_cast<long long>(response.size()))});

            if (sabotage) {
                log_client_event("sabotage_detected", ip, port,
                                 {icsd::jnum("function_code", pdu[0]),
                                  icsd::jnum("address", sabotage_addr),
                                  icsd::jstr("alert", "write_to_critical_register")});
            }
        }
        if (fatal) {
            break;
        }

        if (buffer.size() > kMaxBuffer) {
            log_client_event("modbus_malformed", ip, port,
                             {icsd::jstr("reason", "buffer_overflow"),
                              icsd::jnum("buffered", static_cast<long long>(buffer.size()))});
            close_reason = "buffer_overflow";
            break;
        }

        // 2. Pull more bytes from the stream.
        ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
        if (n == 0) {
            close_reason = "peer_closed";
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (icsd::recv_timed_out()) {
                log_client_event("modbus_timeout", ip, port,
                                 {icsd::jnum("timeout_seconds",
                                             static_cast<long long>(cfg.recv_timeout))});
                close_reason = "timeout";
            } else {
                log_client_event("modbus_connection_error", ip, port,
                                 {icsd::jstr("reason", "recv_failed"),
                                  icsd::jnum("errno", errno)});
                close_reason = "recv_failed";
            }
            break;
        }
        buffer.insert(buffer.end(), chunk, chunk + n);
    }

    ::close(fd);
    g_active_clients.fetch_sub(1);
    log_client_event("connection_closed", ip, port, {icsd::jstr("reason", close_reason)});
}

// -- CLI --------------------------------------------------------------------

void print_usage(const char *program) {
    std::printf(
        "Modbus/TCP deception service (authorized laboratory research only)\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "  --bind ADDR           bind address           (default: 127.0.0.1)\n"
        "  --port PORT           TCP port               (default: 5020)\n"
        "  --error-percent N     random exception rate  (default: 0, disabled)\n"
        "  --min-latency-ms N    minimum reply latency  (default: 0)\n"
        "  --max-latency-ms N    maximum reply latency  (default: 0, disabled)\n"
        "  --seed N              deterministic RNG seed (default: time based)\n"
        "  --max-clients N       simultaneous clients   (default: 16)\n"
        "  --crit-start N        critical range start   (default: 100)\n"
        "  --crit-end N          critical range end     (default: 110)\n"
        "  --timeout SECONDS     per-client recv timeout(default: 30)\n"
        "  --log PATH            JSONL event log        (default: runtime/modbus_honeypot.jsonl)\n"
        "  --help                show this help\n"
        "\n"
        "Port 502 requires root. Bind to 5020 and forward 502 -> 5020 instead;\n"
        "see README.md for the nftables/iptables recipe.\n",
        program);
}

bool parse_args(int argc, char **argv, Config &cfg) {
    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];
        auto need_value = [&](const char *name) -> const char * {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: %s requires a value\n", name);
                return nullptr;
            }
            return argv[++i];
        };

        long value = 0;
        if (flag == "--help" || flag == "-h") {
            print_usage(argv[0]);
            return false;
        } else if (flag == "--bind") {
            const char *v = need_value("--bind");
            if (v == nullptr) return false;
            cfg.bind_addr = v;
        } else if (flag == "--port") {
            const char *v = need_value("--port");
            if (v == nullptr || !icsd::parse_int_arg(v, 1, 65535, value)) {
                std::fprintf(stderr, "error: --port must be 1..65535\n");
                return false;
            }
            cfg.port = static_cast<uint16_t>(value);
        } else if (flag == "--error-percent") {
            const char *v = need_value("--error-percent");
            if (v == nullptr || !icsd::parse_int_arg(v, 0, 100, value)) {
                std::fprintf(stderr, "error: --error-percent must be 0..100\n");
                return false;
            }
            cfg.error_percent = static_cast<int>(value);
        } else if (flag == "--min-latency-ms") {
            const char *v = need_value("--min-latency-ms");
            if (v == nullptr || !icsd::parse_int_arg(v, 0, 60000, value)) {
                std::fprintf(stderr, "error: --min-latency-ms must be 0..60000\n");
                return false;
            }
            cfg.min_latency_ms = value;
        } else if (flag == "--max-latency-ms") {
            const char *v = need_value("--max-latency-ms");
            if (v == nullptr || !icsd::parse_int_arg(v, 0, 60000, value)) {
                std::fprintf(stderr, "error: --max-latency-ms must be 0..60000\n");
                return false;
            }
            cfg.max_latency_ms = value;
        } else if (flag == "--seed") {
            const char *v = need_value("--seed");
            if (v == nullptr || !icsd::parse_int_arg(v, 0, 2147483647L, value)) {
                std::fprintf(stderr, "error: --seed must be 0..2147483647\n");
                return false;
            }
            cfg.seed = static_cast<unsigned long>(value);
            cfg.seed_given = true;
        } else if (flag == "--max-clients") {
            const char *v = need_value("--max-clients");
            if (v == nullptr || !icsd::parse_int_arg(v, 1, 4096, value)) {
                std::fprintf(stderr, "error: --max-clients must be 1..4096\n");
                return false;
            }
            cfg.max_clients = static_cast<int>(value);
        } else if (flag == "--crit-start") {
            const char *v = need_value("--crit-start");
            if (v == nullptr || !icsd::parse_int_arg(v, 0, 65535, value)) {
                std::fprintf(stderr, "error: --crit-start must be 0..65535\n");
                return false;
            }
            cfg.crit_start = static_cast<int>(value);
        } else if (flag == "--crit-end") {
            const char *v = need_value("--crit-end");
            if (v == nullptr || !icsd::parse_int_arg(v, 0, 65535, value)) {
                std::fprintf(stderr, "error: --crit-end must be 0..65535\n");
                return false;
            }
            cfg.crit_end = static_cast<int>(value);
        } else if (flag == "--timeout") {
            const char *v = need_value("--timeout");
            if (v == nullptr || !icsd::parse_int_arg(v, 1, 86400, value)) {
                std::fprintf(stderr, "error: --timeout must be 1..86400 seconds\n");
                return false;
            }
            cfg.recv_timeout = static_cast<double>(value);
        } else if (flag == "--log") {
            const char *v = need_value("--log");
            if (v == nullptr) return false;
            cfg.log_path = v;
        } else {
            std::fprintf(stderr, "error: unknown option '%s' (try --help)\n", flag.c_str());
            return false;
        }
    }

    if (cfg.max_latency_ms > 0 && cfg.min_latency_ms > cfg.max_latency_ms) {
        std::fprintf(stderr, "error: --min-latency-ms exceeds --max-latency-ms\n");
        return false;
    }
    if (cfg.crit_start > cfg.crit_end) {
        std::fprintf(stderr, "error: --crit-start exceeds --crit-end\n");
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char **argv) {
    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        // parse_args prints its own diagnostics; --help is not an error.
        for (int i = 1; i < argc; ++i) {
            if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
                return 0;
            }
        }
        return 2;
    }

    g_rng.seed(cfg.seed_given
                   ? static_cast<std::mt19937::result_type>(cfg.seed)
                   : static_cast<std::mt19937::result_type>(
                         std::chrono::steady_clock::now().time_since_epoch().count()));

    icsd::JsonLogger logger("modbus_honeypot", cfg.log_path);
    g_log = &logger;

    std::string error;
    int listen_fd = icsd::create_listener(cfg.bind_addr, cfg.port, 16, error);
    if (listen_fd < 0) {
        std::fprintf(stderr, "error: %s\n", error.c_str());
        if (cfg.port < 1024) {
            std::fprintf(stderr,
                         "hint: ports below 1024 need root; use --port 5020 and forward 502.\n");
        }
        return 1;
    }

    logger.event("modbus_honeypot_startup",
                 icsd::jjoin({icsd::jstr("bind", cfg.bind_addr), icsd::jnum("port", cfg.port),
                              icsd::jnum("max_clients", cfg.max_clients),
                              icsd::jnum("error_percent", cfg.error_percent),
                              icsd::jnum("crit_start", cfg.crit_start),
                              icsd::jnum("crit_end", cfg.crit_end)}));
    std::printf("Modbus honeypot listening on %s:%u (max %d clients)\n", cfg.bind_addr.c_str(),
                static_cast<unsigned>(cfg.port), cfg.max_clients);
    std::fflush(stdout);

    while (g_running.load()) {
        struct sockaddr_in client_addr;
        std::memset(&client_addr, 0, sizeof(client_addr));
        socklen_t addr_len = sizeof(client_addr);
        int client_fd =
            ::accept(listen_fd, reinterpret_cast<struct sockaddr *>(&client_addr), &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger.event("accept_error", icsd::jjoin({icsd::jnum("errno", errno)}));
            continue;
        }

        const std::string ip = icsd::peer_ip(client_addr);
        const uint16_t port = ntohs(client_addr.sin_port);

        if (g_active_clients.load() >= cfg.max_clients) {
            logger.event("connection_rejected",
                         icsd::jjoin({icsd::jstr("client_ip", ip), icsd::jnum("client_port", port),
                                      icsd::jstr("reason", "max_clients_reached"),
                                      icsd::jnum("max_clients", cfg.max_clients)}));
            ::close(client_fd);
            continue;
        }

        g_active_clients.fetch_add(1);
        try {
            std::thread(handle_client, client_fd, ip, port, cfg).detach();
        } catch (const std::system_error &exc) {
            // Thread creation failure must not take down the service.
            g_active_clients.fetch_sub(1);
            ::close(client_fd);
            logger.event("thread_spawn_failed",
                         icsd::jjoin({icsd::jstr("client_ip", ip), icsd::jstr("error", exc.what())}));
        }
    }

    ::close(listen_fd);
    logger.event("modbus_honeypot_shutdown", icsd::jjoin({icsd::jnum("port", cfg.port)}));
    return 0;
}
