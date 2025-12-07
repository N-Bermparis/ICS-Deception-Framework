// iot-nodes/raspberrypi/fake_ssh.cpp
//
// Minimal SSH-like honeypot. Not a real SSH protocol implementation!
// Listens on 2222, sends SSH banner, then emulates a simple line-based shell.
// Keystrokes and credentials are logged to logging/ssh_sessions.log

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <string>

static const int LISTEN_PORT = 2222;
static const char* LOG_PATH = "logging/ssh_sessions.log";

static void log_line(const std::string &s) {
    FILE* f = std::fopen(LOG_PATH, "a");
    if (!f) return;
    std::fprintf(f, "%s\n", s.c_str());
    std::fclose(f);
}

static void handle_client(int client, const std::string &ip, uint16_t port) {
    char buf[1024];

    // Fake SSH banner
    std::string banner = "SSH-2.0-rtu358_fw1.7\r\n";
    send(client, banner.c_str(), banner.size(), 0);

    // Ask for "username"
    std::string prompt_user = "Username: ";
    send(client, prompt_user.c_str(), prompt_user.size(), 0);
    int n = recv(client, buf, sizeof(buf)-1, 0);
    if (n <= 0) { close(client); return; }
    buf[n] = 0;
    std::string user(buf);
    user.erase(user.find_last_not_of("\r\n") + 1);

    std::string prompt_pass = "Password: ";
    send(client, prompt_pass.c_str(), prompt_pass.size(), 0);
    n = recv(client, buf, sizeof(buf)-1, 0);
    if (n <= 0) { close(client); return; }
    buf[n] = 0;
    std::string pass(buf);
    pass.erase(pass.find_last_not_of("\r\n") + 1);

    log_line("connection from " + ip + ":" + std::to_string(port) +
             " user=" + user + " pass=" + pass);

    std::string welcome =
        "\r\nLast login: Mon Jan  1 00:00:00 2025 from " + ip + "\r\n"
        "rtu358# ";
    send(client, welcome.c_str(), welcome.size(), 0);

    std::string cmdline;
    while (true) {
        n = recv(client, buf, sizeof(buf)-1, 0);
        if (n <= 0) break;
        buf[n] = 0;
        for (int i = 0; i < n; ++i) {
            char c = buf[i];
            if (c == '\r' || c == '\n') {
                if (!cmdline.empty()) {
                    log_line(ip + ":" + std::to_string(port) + " cmd=" + cmdline);
                    std::string resp;
                    if (cmdline == "help") {
                        resp = "\r\nCommands: help, status, show, diag, uptime, exit\r\nrtu358# ";
                    } else if (cmdline == "status") {
                        resp = "\r\nSTATUS: RUN, Modbus ONLINE, DNP3 ONLINE\r\nrtu358# ";
                    } else if (cmdline == "show") {
                        resp = "\r\nSHOW IO: DO0=1, DO1=0, DI0=1\r\nrtu358# ";
                    } else if (cmdline == "diag") {
                        resp = "\r\nDIAG: CPU 23%, MEM 48%\r\nrtu358# ";
                    } else if (cmdline == "uptime") {
                        resp = "\r\nUptime: 86400s\r\nrtu358# ";
                    } else if (cmdline == "exit") {
                        resp = "\r\nlogout\r\n";
                        send(client, resp.c_str(), resp.size(), 0);
                        close(client);
                        return;
                    } else {
                        resp = "\r\nUnknown command.\r\nrtu358# ";
                    }
                    send(client, resp.c_str(), resp.size(), 0);
                    cmdline.clear();
                } else {
                    std::string p = "rtu358# ";
                    send(client, p.c_str(), p.size(), 0);
                }
            } else if (c == 0x7f || c == 0x08) {
                if (!cmdline.empty()) cmdline.pop_back();
            } else {
                cmdline.push_back(c);
            }
        }
    }
    close(client);
}

int main() {
    system("mkdir -p logging");

    int server = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(server, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server, 5) < 0) {
        perror("listen");
        return 1;
    }

    printf("Fake SSH honeypot listening on %d\n", LISTEN_PORT);

    while (true) {
        sockaddr_in cli{};
        socklen_t len = sizeof(cli);
        int client = accept(server, (sockaddr*)&cli, &len);
        if (client < 0) continue;
        std::string ip = inet_ntoa(cli.sin_addr);
        uint16_t port = ntohs(cli.sin_port);
        handle_client(client, ip, port);
    }
}
