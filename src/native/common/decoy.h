// decoy.h — shared scaffolding for the interactive line-based decoys.
//
// Both the Telnet decoy and the SSH-banner decoy present a fake device shell.
// The transport handling (bounded line reading, timeouts, client limits, JSONL
// logging, argument parsing) is identical, so it lives here; only the banner,
// the prompt and the command responses differ per service.
//
// Credential policy: the submitted password is NOT stored by default. Only its
// length and a coarse character-class summary are logged. Passing
// --capture-credentials opts a controlled experiment into plaintext capture and
// makes the decision explicit in the event stream.

#ifndef ICS_DECEPTION_DECOY_H
#define ICS_DECEPTION_DECOY_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
// std::system_error is thrown by std::thread's constructor and caught below.
// Do not rely on <thread> pulling it in transitively: that is a libstdc++
// implementation detail, not a guarantee.
#include <system_error>
#include <thread>
#include <vector>

#include "net_util.h"

namespace icsd {

// Maximum characters accepted on one input line before the peer is dropped.
constexpr size_t kMaxLineLength = 512;
// Maximum commands serviced in a single session.
constexpr int kMaxCommandsPerSession = 200;

struct DecoyConfig {
    std::string bind_addr = "127.0.0.1";
    uint16_t port = 0;  // set by each service's default
    int max_clients = 16;
    double recv_timeout = 30.0;
    std::string log_path;
    // Off by default: do not persist plaintext passwords.
    bool capture_credentials = false;
};

enum class LineStatus { kOk, kClosed, kTimeout, kError, kTooLong };

// Read one CR/LF-terminated line, bounded to kMaxLineLength characters.
// Backspace/DEL edit the buffer; other control characters are dropped.
inline LineStatus read_line(int fd, std::string &out) {
    out.clear();
    for (;;) {
        char c = 0;
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n == 0) {
            return LineStatus::kClosed;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return recv_timed_out() ? LineStatus::kTimeout : LineStatus::kError;
        }
        if (c == '\n' || c == '\r') {
            if (c == '\r') {
                // Consume the paired LF of a CRLF if it has already arrived,
                // so the peer does not get an extra empty line and prompt.
                char peeked = 0;
                ssize_t p = ::recv(fd, &peeked, 1, MSG_PEEK | MSG_DONTWAIT);
                if (p == 1 && peeked == '\n') {
                    ssize_t discarded = ::recv(fd, &peeked, 1, MSG_DONTWAIT);
                    (void)discarded;
                }
            }
            return LineStatus::kOk;
        }
        if (c == 0x7f || c == 0x08) {
            if (!out.empty()) {
                out.pop_back();
            }
            continue;
        }
        if (static_cast<unsigned char>(c) < 0x20) {
            continue;  // ignore telnet negotiation and other control bytes
        }
        out.push_back(c);
        if (out.size() > kMaxLineLength) {
            return LineStatus::kTooLong;
        }
    }
}

// Coarse, non-reversible description of a submitted password.
inline std::string password_shape(const std::string &password) {
    bool lower = false, upper = false, digit = false, other = false;
    for (unsigned char c : password) {
        if (c >= 'a' && c <= 'z') {
            lower = true;
        } else if (c >= 'A' && c <= 'Z') {
            upper = true;
        } else if (c >= '0' && c <= '9') {
            digit = true;
        } else {
            other = true;
        }
    }
    std::string shape;
    if (lower) shape += "a";
    if (upper) shape += "A";
    if (digit) shape += "0";
    if (other) shape += "#";
    return shape.empty() ? "none" : shape;
}

// Emit a login attempt, honouring the credential-capture policy.
inline void log_login_attempt(JsonLogger &logger, const std::string &ip, uint16_t port,
                              const std::string &user, const std::string &password,
                              bool capture_credentials) {
    std::vector<std::string> parts{
        jstr("client_ip", ip),
        jnum("client_port", port),
        jstr("username", user),
        jnum("password_length", static_cast<long long>(password.size())),
        jstr("password_shape", password_shape(password)),
        jnum("credentials_captured", capture_credentials ? 1 : 0),
    };
    if (capture_credentials) {
        parts.push_back(jstr("password", password));
    }
    logger.event("login_attempt", jjoin(parts));
}

// Per-session callback: implements one service's banner, prompts and commands.
using SessionHandler = void (*)(int fd, const std::string &ip, uint16_t port,
                                const DecoyConfig &cfg, JsonLogger &logger);

inline std::atomic<int> &decoy_active_clients() {
    static std::atomic<int> counter{0};
    return counter;
}

// Accept loop with a simultaneous-client limit. One detached thread per client.
inline int run_decoy_server(const DecoyConfig &cfg, JsonLogger &logger,
                            const std::string &service_name, SessionHandler handler) {
    std::string error;
    int listen_fd = create_listener(cfg.bind_addr, cfg.port, 16, error);
    if (listen_fd < 0) {
        std::fprintf(stderr, "error: %s\n", error.c_str());
        if (cfg.port < 1024) {
            std::fprintf(stderr, "hint: ports below 1024 require root privileges.\n");
        }
        return 1;
    }

    logger.event(service_name + "_startup",
                 jjoin({jstr("bind", cfg.bind_addr), jnum("port", cfg.port),
                        jnum("max_clients", cfg.max_clients),
                        jnum("capture_credentials", cfg.capture_credentials ? 1 : 0)}));
    std::printf("%s decoy listening on %s:%u\n", service_name.c_str(), cfg.bind_addr.c_str(),
                static_cast<unsigned>(cfg.port));
    std::fflush(stdout);

    for (;;) {
        struct sockaddr_in client_addr;
        std::memset(&client_addr, 0, sizeof(client_addr));
        socklen_t addr_len = sizeof(client_addr);
        int fd = ::accept(listen_fd, reinterpret_cast<struct sockaddr *>(&client_addr), &addr_len);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger.event("accept_error", jjoin({jnum("errno", errno)}));
            continue;
        }

        const std::string ip = peer_ip(client_addr);
        const uint16_t port = ntohs(client_addr.sin_port);

        if (decoy_active_clients().load() >= cfg.max_clients) {
            logger.event("connection_rejected",
                         jjoin({jstr("client_ip", ip), jnum("client_port", port),
                                jstr("reason", "max_clients_reached")}));
            ::close(fd);
            continue;
        }

        decoy_active_clients().fetch_add(1);
        try {
            std::thread(
                [fd, ip, port, cfg, &logger, handler]() {
                    set_recv_timeout(fd, cfg.recv_timeout);
                    set_send_timeout(fd, cfg.recv_timeout);
                    handler(fd, ip, port, cfg, logger);
                    ::close(fd);
                    decoy_active_clients().fetch_sub(1);
                })
                .detach();
        } catch (const std::system_error &exc) {
            decoy_active_clients().fetch_sub(1);
            ::close(fd);
            logger.event("thread_spawn_failed",
                         jjoin({jstr("client_ip", ip), jstr("error", exc.what())}));
        }
    }
}

// Shared option parsing. Returns false when the caller should exit; `exit_code`
// distinguishes --help (0) from a usage error (2).
inline bool parse_decoy_args(int argc, char **argv, DecoyConfig &cfg, const char *service_name,
                             int &exit_code) {
    exit_code = 0;
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
            std::printf(
                "%s decoy (authorized laboratory research only)\n"
                "\n"
                "Usage: %s [options]\n"
                "\n"
                "  --bind ADDR             bind address        (default: 127.0.0.1)\n"
                "  --port PORT             TCP port            (default: %u)\n"
                "  --max-clients N         simultaneous clients(default: 16)\n"
                "  --timeout SECONDS       per-client timeout  (default: 30)\n"
                "  --log PATH              JSONL event log\n"
                "  --capture-credentials   store plaintext passwords (OFF by default)\n"
                "  --help                  show this help\n",
                service_name, argv[0], static_cast<unsigned>(cfg.port));
            exit_code = 0;
            return false;
        } else if (flag == "--bind") {
            const char *v = need_value("--bind");
            if (v == nullptr) {
                exit_code = 2;
                return false;
            }
            cfg.bind_addr = v;
        } else if (flag == "--port") {
            const char *v = need_value("--port");
            if (v == nullptr || !parse_int_arg(v, 1, 65535, value)) {
                std::fprintf(stderr, "error: --port must be 1..65535\n");
                exit_code = 2;
                return false;
            }
            cfg.port = static_cast<uint16_t>(value);
        } else if (flag == "--max-clients") {
            const char *v = need_value("--max-clients");
            if (v == nullptr || !parse_int_arg(v, 1, 4096, value)) {
                std::fprintf(stderr, "error: --max-clients must be 1..4096\n");
                exit_code = 2;
                return false;
            }
            cfg.max_clients = static_cast<int>(value);
        } else if (flag == "--timeout") {
            const char *v = need_value("--timeout");
            if (v == nullptr || !parse_int_arg(v, 1, 86400, value)) {
                std::fprintf(stderr, "error: --timeout must be 1..86400 seconds\n");
                exit_code = 2;
                return false;
            }
            cfg.recv_timeout = static_cast<double>(value);
        } else if (flag == "--log") {
            const char *v = need_value("--log");
            if (v == nullptr) {
                exit_code = 2;
                return false;
            }
            cfg.log_path = v;
        } else if (flag == "--capture-credentials") {
            cfg.capture_credentials = true;
        } else {
            std::fprintf(stderr, "error: unknown option '%s' (try --help)\n", flag.c_str());
            exit_code = 2;
            return false;
        }
    }
    return true;
}

}  // namespace icsd

#endif  // ICS_DECEPTION_DECOY_H
