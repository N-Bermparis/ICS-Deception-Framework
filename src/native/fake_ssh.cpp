// fake_ssh.cpp — SSH-banner decoy.
//
// IMPORTANT: this is NOT an SSH server. It emits an SSH identification string
// and then speaks a plain-text line protocol. There is no SSH key exchange
// (RFC 4253), no binary packet protocol, no encryption, no MAC, and no
// authentication protocol. A real SSH client will send its own identification
// string and then fail at key exchange.
//
// What it is good for: capturing the identification banner of whatever
// connected, and recording the credentials and commands that automated
// scanners blindly push at anything answering on an SSH-looking port.
//
// Safe defaults: loopback bind, unprivileged port 2222, bounded line lengths,
// receive timeouts, capped simultaneous clients, and no plaintext password
// storage unless --capture-credentials is passed explicitly.

#include <unistd.h>

#include <cstdio>
#include <string>

#include "common/decoy.h"
#include "common/net_util.h"

namespace {

constexpr uint16_t kDefaultPort = 2222;
const char *const kPrompt = "rtu358# ";
// Deliberately plausible, deliberately fictitious.
const char *const kIdentification = "SSH-2.0-rtu358_fw1.7\r\n";

std::string respond(const std::string &command) {
    if (command == "help") {
        return "\r\nCommands: help, status, show, diag, uptime, exit\r\n";
    }
    if (command == "status") {
        return "\r\nSTATUS: RUN, Modbus ONLINE, DNP3 ONLINE\r\n";
    }
    if (command == "show") {
        return "\r\nSHOW IO: DO0=1, DO1=0, DI0=1\r\n";
    }
    if (command == "diag") {
        return "\r\nDIAG: CPU 23%, MEM 48%\r\n";
    }
    if (command == "uptime") {
        return "\r\nUptime: 86400s\r\n";
    }
    return "\r\nUnknown command.\r\n";
}

// A real SSH client answers our identification string with its own
// ("SSH-2.0-OpenSSH_9.6") and then starts binary key exchange, which this decoy
// cannot speak. That first line is the single most useful artefact we get from
// a genuine client, so it is recorded whenever it appears — not only when the
// read fails.
void record_peer_identification(icsd::JsonLogger &logger, const std::string &ip, uint16_t port,
                                const std::string &line) {
    if (line.rfind("SSH-", 0) != 0) {
        return;
    }
    logger.event("ssh_banner_peer_identification",
                 icsd::jjoin({icsd::jstr("client_ip", ip), icsd::jnum("client_port", port),
                              icsd::jstr("first_line", line),
                              icsd::jstr("note", "peer sent an SSH identification string; "
                                                 "this decoy performs no key exchange")}));
}

void session(int fd, const std::string &ip, uint16_t port, const icsd::DecoyConfig &cfg,
             icsd::JsonLogger &logger) {
    logger.event("ssh_banner_connection",
                 icsd::jjoin({icsd::jstr("client_ip", ip), icsd::jnum("client_port", port),
                              icsd::jstr("note", "SSH-banner decoy; no key exchange performed")}));

    std::string close_reason = "peer_closed";
    std::string username;
    std::string password;

    bool login_complete = false;
    if (!icsd::send_all(fd, kIdentification) || !icsd::send_all(fd, "Username: ")) {
        close_reason = "send_failed";
    } else {
        const icsd::LineStatus user_status = icsd::read_line(fd, username);
        // Record the peer's first line either way: on a complete line it is
        // usually a genuine SSH identification string, and on a truncated one it
        // still shows what the peer tried to send.
        record_peer_identification(logger, ip, port, username);
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

        const std::string welcome =
            std::string("\r\nLast login: Mon Jan  1 00:00:00 2035 from ") + ip + "\r\n" + kPrompt;
        if (icsd::send_all(fd, welcome)) {
            int commands = 0;
            for (;;) {
                std::string command;
                const icsd::LineStatus status = icsd::read_line(fd, command);
                if (status == icsd::LineStatus::kTimeout) {
                    close_reason = "timeout";
                    logger.event("ssh_banner_timeout",
                                 icsd::jjoin({icsd::jstr("client_ip", ip),
                                              icsd::jnum("client_port", port)}));
                    break;
                }
                if (status == icsd::LineStatus::kTooLong) {
                    close_reason = "line_too_long";
                    logger.event("ssh_banner_line_too_long",
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
                    logger.event("ssh_banner_command_limit",
                                 icsd::jjoin({icsd::jstr("client_ip", ip),
                                              icsd::jnum("client_port", port),
                                              icsd::jnum("limit", icsd::kMaxCommandsPerSession)}));
                    break;
                }

                logger.event("ssh_banner_command",
                             icsd::jjoin({icsd::jstr("client_ip", ip),
                                          icsd::jnum("client_port", port),
                                          icsd::jstr("command", command),
                                          icsd::jnum("sequence", commands)}));

                if (command == "exit" || command == "quit" || command == "logout") {
                    icsd::send_all(fd, "\r\nlogout\r\n");
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

    logger.event("ssh_banner_connection_closed",
                 icsd::jjoin({icsd::jstr("client_ip", ip), icsd::jnum("client_port", port),
                              icsd::jstr("reason", close_reason)}));
}

}  // namespace

int main(int argc, char **argv) {
    icsd::DecoyConfig cfg;
    cfg.port = kDefaultPort;
    cfg.log_path = "runtime/ssh_banner_decoy.jsonl";

    int exit_code = 0;
    if (!icsd::parse_decoy_args(argc, argv, cfg, "SSH-banner", exit_code)) {
        return exit_code;
    }

    icsd::JsonLogger logger("fake_ssh_banner", cfg.log_path);
    return icsd::run_decoy_server(cfg, logger, "ssh_banner", session);
}
