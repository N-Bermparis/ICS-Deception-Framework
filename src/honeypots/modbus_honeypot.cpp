// honeypots/modbus_honeypot.cpp
//
// Modbus/TCP honeypot for ICS/SCADA PLC emulation.
// Supports FC: 0x01, 0x03, 0x05, 0x06, 0x10
//
// Linux/RPi: blocking sockets, main() entry.
// ESP32 (Arduino): FreeRTOS task, call startModbusHoneypotTask() from setup().
//
// Logs JSON lines into ./logging/modbus_log.jsonl

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>

#include <string>
#include <vector>

#ifdef ARDUINO
  #include <Arduino.h>
  #include <WiFi.h>
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "lwip/sockets.h"
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <errno.h>
#endif

static const int MODBUS_PORT = 502;
static const size_t COILS_SIZE = 256;
static const size_t HOLDING_REG_SIZE = 256;

// Fake critical region: holding registers [100..110]
static const int CRIT_REG_START = 100;
static const int CRIT_REG_END   = 110;

// Internal state
static bool coils[COILS_SIZE];
static uint16_t holding[HOLDING_REG_SIZE];

// Logging file path (Linux/RPi; ESP32 uses Serial)
#ifndef ARDUINO
static const char* LOG_PATH = "logging/modbus_log.jsonl";
#endif

static void init_state() {
    for (size_t i = 0; i < COILS_SIZE; ++i) coils[i] = false;
    for (size_t i = 0; i < HOLDING_REG_SIZE; ++i) holding[i] = 0;
}

// Simple random helper
static int rnd(int max) {
    return rand() % max;
}

static std::string now_utc_iso() {
    char buf[64];
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

static void log_json(const std::string &line) {
#ifdef ARDUINO
    Serial.println(line.c_str());
#else
    FILE* f = std::fopen(LOG_PATH, "a");
    if (!f) return;
    std::fprintf(f, "%s\n", line.c_str());
    std::fclose(f);
#endif
}

// Minimal JSON escaping
static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default: out += c; break;
        }
    }
    return out;
}

static void log_event(const std::string &event_type,
                      const std::string &client_ip,
                      uint16_t client_port,
                      uint8_t func_code,
                      const std::string &extra = "{}")
{
    std::string ts = now_utc_iso();
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "{\"timestamp\":\"%s\",\"source\":\"modbus_honeypot\","
                  "\"event_type\":\"%s\",\"details\":{"
                  "\"client_ip\":\"%s\",\"client_port\":%u,"
                  "\"func_code\":%u,%s}}",
                  ts.c_str(), event_type.c_str(),
                  client_ip.c_str(), client_port,
                  (unsigned)func_code, extra.c_str());
    log_json(buf);
}

// Simulate network/PLC latency and random errors
static void maybe_sleep_latency() {
#ifdef ARDUINO
    vTaskDelay(pdMS_TO_TICKS(50 + rnd(150)));
#else
    usleep((50 + rnd(150)) * 1000);
#endif
}

static bool maybe_inject_error() {
    // ~5% chance to return Modbus exception error rather than normal reply
    return rnd(100) < 5;
}

// Build Modbus exception response (function | 0x80, exception code 0x02)
static std::vector<uint8_t> build_exception_response(
    const std::vector<uint8_t> &req, uint8_t exception_code)
{
    // MBAP: 0..5, unit:6, func:7
    std::vector<uint8_t> resp = req;
    if (resp.size() < 8) resp.resize(8, 0);
    resp[4] = 0; // Length high
    resp[5] = 3; // Length low: unit + func + code
    resp[7] = (uint8_t)(resp[7] | 0x80);
    if (resp.size() < 9) resp.push_back(exception_code);
    else resp[8] = exception_code;
    return resp;
}

// Helpers to read big-endian
static uint16_t be16(const uint8_t* p) {
    return (uint16_t)(p[0] << 8 | p[1]);
}

// Handlers for function codes
static std::vector<uint8_t> handle_fc01(const std::vector<uint8_t> &req) {
    // Read Coils: addr(2), qty(2)
    if (req.size() < 8 + 4)
        return build_exception_response(req, 0x02);
    uint8_t unit_id = req[6];
    uint8_t func = req[7];
    uint16_t addr = be16(&req[8]);
    uint16_t qty  = be16(&req[10]);
    if (qty == 0 || qty > 2000) {
        return build_exception_response(req, 0x03);
    }
    if ((size_t)addr + qty > COILS_SIZE) {
        return build_exception_response(req, 0x02);
    }

    uint16_t byte_count = (uint16_t)((qty + 7) / 8);
    std::vector<uint8_t> resp;
    resp.resize(9 + byte_count); // MBAP 0-5, unit 6, func 7, byte_count 8, data...
    // Copy transaction, proto, unit, func
    for (int i = 0; i < 7; ++i) resp[i] = req[i];
    resp[7] = func;
    resp[8] = (uint8_t)byte_count;

    for (uint16_t i = 0; i < qty; ++i) {
        size_t idx = addr + i;
        bool val = coils[idx];
        if (val) {
            resp[9 + (i / 8)] |= (1 << (i % 8));
        }
    }
    // Length field
    uint16_t len = (uint16_t)(3 + byte_count); // unit+func+byte_count+data
    resp[4] = (uint8_t)(len >> 8);
    resp[5] = (uint8_t)(len & 0xff);

    // Simulate subtle ICS fingerprint by leaving reserved fields as-is
    (void)unit_id;
    return resp;
}

static std::vector<uint8_t> handle_fc03(const std::vector<uint8_t> &req) {
    // Read Holding Registers: addr(2), qty(2)
    if (req.size() < 8 + 4)
        return build_exception_response(req, 0x02);
    uint8_t func = req[7];
    uint16_t addr = be16(&req[8]);
    uint16_t qty  = be16(&req[10]);
    if (qty == 0 || qty > 125) {
        return build_exception_response(req, 0x03);
    }
    if ((size_t)addr + qty > HOLDING_REG_SIZE) {
        return build_exception_response(req, 0x02);
    }

    uint8_t byte_count = (uint8_t)(qty * 2);
    std::vector<uint8_t> resp;
    resp.resize(9 + byte_count);
    for (int i = 0; i < 7; ++i) resp[i] = req[i];
    resp[7] = func;
    resp[8] = byte_count;

    for (uint16_t i = 0; i < qty; ++i) {
        uint16_t val = holding[addr + i];
        resp[9 + 2 * i]     = (uint8_t)(val >> 8);
        resp[9 + 2 * i + 1] = (uint8_t)(val & 0xff);
    }

    uint16_t len = (uint16_t)(3 + byte_count);
    resp[4] = (uint8_t)(len >> 8);
    resp[5] = (uint8_t)(len & 0xff);
    return resp;
}

static std::vector<uint8_t> handle_fc05(const std::vector<uint8_t> &req,
                                        bool &sabotage_detected)
{
    // Write Single Coil: addr(2), value(2)
    if (req.size() < 8 + 4)
        return build_exception_response(req, 0x02);
    uint16_t addr = be16(&req[8]);
    uint16_t value = be16(&req[10]);
    if (addr >= COILS_SIZE)
        return build_exception_response(req, 0x02);
    bool on = (value == 0xFF00);
    coils[addr] = on;

    // Simple sabotage detection: writing in [CRIT_REG_START..END) coils region
    if (addr >= CRIT_REG_START && addr <= CRIT_REG_END) {
        sabotage_detected = true;
    }

    // Echo request as response
    return req;
}

static std::vector<uint8_t> handle_fc06(const std::vector<uint8_t> &req,
                                        bool &sabotage_detected)
{
    // Write Single Register: addr(2), value(2)
    if (req.size() < 8 + 4)
        return build_exception_response(req, 0x02);
    uint16_t addr = be16(&req[8]);
    uint16_t value = be16(&req[10]);
    if (addr >= HOLDING_REG_SIZE)
        return build_exception_response(req, 0x02);
    holding[addr] = value;

    if (addr >= CRIT_REG_START && addr <= CRIT_REG_END) {
        sabotage_detected = true;
    }

    return req;
}

static std::vector<uint8_t> handle_fc10(const std::vector<uint8_t> &req,
                                        bool &sabotage_detected)
{
    // Write Multiple Registers: addr(2), qty(2), byte_count(1), values...
    if (req.size() < 8 + 5)
        return build_exception_response(req, 0x02);
    uint16_t addr = be16(&req[8]);
    uint16_t qty  = be16(&req[10]);
    uint8_t byte_count = req[12];
    if (qty == 0 || qty > 123 || byte_count != qty * 2)
        return build_exception_response(req, 0x03);
    if (req.size() < 8 + 5 + byte_count)
        return build_exception_response(req, 0x02);
    if ((size_t)addr + qty > HOLDING_REG_SIZE)
        return build_exception_response(req, 0x02);

    const uint8_t* p = &req[13];
    for (uint16_t i = 0; i < qty; ++i) {
        uint16_t val = be16(p + 2*i);
        holding[addr + i] = val;
        if (addr + i >= CRIT_REG_START && addr + i <= CRIT_REG_END) {
            sabotage_detected = true;
        }
    }

    // Response: echo addr and qty, same MBAP except length=6
    std::vector<uint8_t> resp = req;
    resp.resize(12);
    resp[4] = 0;
    resp[5] = 6; // unit + func + addr(2) + qty(2)
    return resp;
}

static std::vector<uint8_t> process_modbus(const std::vector<uint8_t> &req,
                                           bool &sabotage_detected)
{
    if (req.size() < 8)
        return build_exception_response(req, 0x02);

    uint8_t func = req[7];

    if (maybe_inject_error()) {
        return build_exception_response(req, 0x04); // Slave device failure
    }

    switch (func) {
        case 0x01: return handle_fc01(req);
        case 0x03: return handle_fc03(req);
        case 0x05: return handle_fc05(req, sabotage_detected);
        case 0x06: return handle_fc06(req, sabotage_detected);
        case 0x10: return handle_fc10(req, sabotage_detected);
        default:
            return build_exception_response(req, 0x01); // illegal function
    }
}

static void handle_client(int client_sock, const std::string &client_ip, uint16_t client_port)
{
    uint8_t buf[260];
    while (true) {
        int n = recv(client_sock, (char*)buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (n < 8) continue;

        std::vector<uint8_t> req(buf, buf + n);
        uint8_t func = req[7];
        bool sabotage = false;
        log_event("modbus_request", client_ip, client_port, func,
                  "\"bytes_in\":" + std::to_string(n));
        maybe_sleep_latency();
        std::vector<uint8_t> resp = process_modbus(req, sabotage);
        if (!resp.empty()) {
            send(client_sock, (const char*)resp.data(), resp.size(), 0);
            log_event("modbus_response", client_ip, client_port, func,
                      "\"bytes_out\":" + std::to_string(resp.size()));
        }
        if (sabotage) {
            log_event("sabotage_detected", client_ip, client_port, func,
                      "\"alert\":\"write_to_critical_region\"");
        }
    }
#ifdef ARDUINO
    lwip_close(client_sock);
#else
    close(client_sock);
#endif
}

// Linux / Raspberry Pi implementation
#ifndef ARDUINO

int main() {
    srand((unsigned)time(nullptr));
    init_state();

    // Ensure log dir exists
    system("mkdir -p logging");

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(MODBUS_PORT);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        return 1;
    }

    printf("Modbus honeypot listening on port %d\n", MODBUS_PORT);

    while (true) {
        sockaddr_in cli{};
        socklen_t cli_len = sizeof(cli);
        int client = accept(server_fd, (sockaddr*)&cli, &cli_len);
        if (client < 0) {
            perror("accept");
            continue;
        }
        std::string ip = inet_ntoa(cli.sin_addr);
        uint16_t port = ntohs(cli.sin_port);
        log_event("connection", ip, port, 0, "\"banner\":\"RTU-358 Control Module v1.7\"");
        handle_client(client, ip, port);
    }

    close(server_fd);
    return 0;
}

#else // ESP32 / Arduino implementation

static void modbus_task(void *param) {
    srand((unsigned)time(nullptr));
    init_state();

    int server_fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        Serial.println("socket failed");
        vTaskDelete(nullptr);
        return;
    }

    int opt = 1;
    lwip_setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(MODBUS_PORT);

    if (lwip_bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        Serial.println("bind failed");
        vTaskDelete(nullptr);
        return;
    }

    if (lwip_listen(server_fd, 5) < 0) {
        Serial.println("listen failed");
        vTaskDelete(nullptr);
        return;
    }

    Serial.printf("Modbus honeypot listening on port %d\n", MODBUS_PORT);

    while (true) {
        sockaddr_in cli{};
        socklen_t cli_len = sizeof(cli);
        int client = lwip_accept(server_fd, (sockaddr*)&cli, &cli_len);
        if (client < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        std::string ip = inet_ntoa(cli.sin_addr);
        uint16_t port = ntohs(cli.sin_port);
        log_event("connection", ip, port, 0, "\"banner\":\"RTU-358 Control Module v1.7\"");
        handle_client(client, ip, port);
    }
}

void startModbusHoneypotTask() {
    xTaskCreate(modbus_task, "modbus_honeypot", 8192, nullptr, 1, nullptr);
}

#endif
