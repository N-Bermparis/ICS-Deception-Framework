// fake_telnet.cpp — Telnet-style interactive decoy.
//
// Presents a fake RTU maintenance shell over a plain TCP line protocol. It does
// not implement Telnet option negotiation (RFC 854); IAC sequences are simply
// discarded as control bytes. Its purpose is to record what an interactive
// intruder types, not to be a Telnet server.
//
// Safe defaults: loopback bind, unprivileged port 2323, bounded line lengths,
// receive timeouts, capped simultaneous clients, and no plaintext password
// storage unless --capture-credentials is passed explicitly.

#include <unistd.h>

#include <cstdio>
#include <string>

#include "common/decoy.h"
#include "common/net_util.h"

namespace {

constexpr uint16_t kDefaultPort = 2323;
const char *const kPrompt = "> ";

// Fake command responses. Nothing here touches the host system.
std::string respond(const std::string &command) {
    if (command == "help") {
        return "\r\nCommands: help, status, show, diag, uptime, exit\r\n";
    }
    if (command == "status") {
        return "\r\nSTATUS: PLC RUN, 4 tasks, 0 alarms.\r\n";
    }
    if (command == "show") {
        return "\r\nSHOW: AI0=4.1mA, AI1=7.3mA.\r\n";
    }
    if (command == "diag") {
        return "\r\nDIAG: Watchdog OK, Modbus OK.\r\n";
    }
    if (command == "uptime") {
        return "\r\nUptime: 1337s\r\n";
    }
    return "\r\nUnknown command.\r\n";
}

void session(int fd, const std::string &ip, uint16_t port, const icsd::DecoyConfig &cfg,
             icsd::JsonLogger &logger) {
    logger.event("telnet_connection",
                 icsd::jjoin({icsd::jstr("client_ip", ip), icsd::jnum("client_port", port)}));

    std::string close_reason = "peer_closed";
    std::string username;
    std::string password;

    bool login_complete = false;
    if (!icsd::send_all(fd, "RTU-358 Control Module v1.7\r\nLogin: ")) {
        close_reason = "send_failed";
    } else {
        // Distinguish an over-long line from a peer that simply hung up: the
        // former is an input-bound violation worth reporting as such.
        const icsd::LineStatus user_status = icsd::read_line(fd, username);
        if (user_status != icsd::LineStatus::kOk) {
            close_reason = (user_status == icsd::LineStatus::kTooLong) ? "line_too_long"
                                                                      : "login_incomplete";
        } else if (!icsd::send_all(fd, "Password: ")) {
            close_reason = "send_failed";
        } else {
            const icsd::LineStatus pass_status = icsd::read_line(fd, password);
            if (pass_status != icsd::LineStatus::kOk) {
                close_reason = (pass_status == icsd::LineStatus::kTooLong) ? "line_too_long"
                                                                          : "login_incomplete";
            } else {
                login_complete = true;
            }
        }
    }

    if (login_complete) {
        icsd::log_login_attempt(logger, ip, port, username, password, cfg.capture_credentials);

        if (icsd::send_all(fd, "\r\nAccess granted.\r\nType 'help' for available commands.\r\n> ")) {
            int commands = 0;
            for (;;) {
                std::string command;
                const icsd::LineStatus status = icsd::read_line(fd, command);
                if (status == icsd::LineStatus::kTimeout) {
                    close_reason = "timeout";
                    logger.event("telnet_timeout",
                                 icsd::jjoin({icsd::jstr("client_ip", ip),
                                              icsd::jnum("client_port", port)}));
                    break;
                }
                if (status == icsd::LineStatus::kTooLong) {
                    close_reason = "line_too_long";
                    logger.event("telnet_line_too_long",
                                 icsd::jjoin({icsd::jstr("client_ip", ip),
                                              icsd::jnum("client_port", port),
                                              icsd::jnum("limit", static_cast<long long>(
                                                                     icsd::kMaxLineLength))}));
                    break;
                }
                if (status != icsd::LineStatus::kOk) {
                    close_reason = (status == icsd::LineStatus::kClosed) ? "peer_closed" : "error";
                    break;
                }
                if (command.empty()) {
                    if (!icsd::send_all(fd, kPrompt)) {
                        close_reason = "send_failed";
                        break;
                    }
                    continue;
                }

                if (++commands > icsd::kMaxCommandsPerSession) {
                    close_reason = "command_limit";
                    logger.event("telnet_command_limit",
                                 icsd::jjoin({icsd::jstr("client_ip", ip),
                                              icsd::jnum("client_port", port),
                                              icsd::jnum("limit", icsd::kMaxCommandsPerSession)}));
                    break;
                }

                logger.event("telnet_command",
                             icsd::jjoin({icsd::jstr("client_ip", ip),
                                          icsd::jnum("client_port", port),
                                          icsd::jstr("command", command),
                                          icsd::jnum("sequence", commands)}));

                if (command == "exit" || command == "quit") {
                    icsd::send_all(fd, "\r\nGoodbye.\r\n");
                    close_reason = "client_exit";
                    break;
                }
                if (!icsd::send_all(fd, respond(command) + kPrompt)) {
                    close_reason = "send_failed";
                    break;
                }
            }
        } else {
            close_reason = "send_failed";
        }
    }

    logger.event("telnet_connection_closed",
                 icsd::jjoin({icsd::jstr("client_ip", ip), icsd::jnum("client_port", port),
                              icsd::jstr("reason", close_reason)}));
}

}  // namespace

int main(int argc, char **argv) {
    icsd::DecoyConfig cfg;
    cfg.port = kDefaultPort;
    cfg.log_path = "runtime/telnet_decoy.jsonl";

    int exit_code = 0;
    if (!icsd::parse_decoy_args(argc, argv, cfg, "Telnet", exit_code)) {
        return exit_code;
    }

    icsd::JsonLogger logger("fake_telnet", cfg.log_path);
    return icsd::run_decoy_server(cfg, logger, "telnet", session);
}
