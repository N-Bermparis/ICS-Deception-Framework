// net_util.h — shared helpers for the native deception services.
//
// Header-only, POSIX sockets, no external dependencies. Everything is `inline`
// (not `static`) so that a translation unit which does not use a helper does
// not trigger -Wunused-function under -Wall -Wextra -Wpedantic.

#ifndef ICS_DECEPTION_NET_UTIL_H
#define ICS_DECEPTION_NET_UTIL_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

namespace icsd {

// --------------------------------------------------------------------------
// Time and JSON helpers
// --------------------------------------------------------------------------

// Current UTC time with millisecond precision, ISO 8601 with a "Z" suffix.
inline std::string now_utc_iso() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    std::tm tm_buf;
    time_t secs = static_cast<time_t>(ts.tv_sec);
    gmtime_r(&secs, &tm_buf);

    char date_buf[32];
    std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    char out[64];
    std::snprintf(out, sizeof(out), "%s.%03ldZ", date_buf,
                  static_cast<long>(ts.tv_nsec / 1000000L));
    return std::string(out);
}

// Escape a string for embedding in a JSON string literal. Control characters
// are emitted as \u00XX so attacker-supplied bytes can never break the line.
inline std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x", static_cast<unsigned>(c));
                    out += esc;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

inline std::string to_hex(const uint8_t *data, size_t len) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += digits[(data[i] >> 4) & 0x0f];
        out += digits[data[i] & 0x0f];
    }
    return out;
}

// --------------------------------------------------------------------------
// Filesystem helpers
// --------------------------------------------------------------------------

// Create every component of a directory path (the equivalent of `mkdir -p`).
// Returns true when the directory exists afterwards.
inline bool make_dirs(const std::string &dir) {
    if (dir.empty()) {
        return true;
    }
    for (size_t i = 0; i <= dir.size(); ++i) {
        if (i != dir.size() && dir[i] != '/') {
            continue;
        }
        if (i == 0) {
            continue;  // leading '/' of an absolute path
        }
        const std::string partial = dir.substr(0, i);
        if (::mkdir(partial.c_str(), 0755) != 0 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

// Create the parent directory of a file path, if it has one.
inline bool make_parent_dirs(const std::string &path) {
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) {
        return true;  // relative name in the current directory
    }
    return make_dirs(path.substr(0, slash));
}

// --------------------------------------------------------------------------
// JSONL event logger
// --------------------------------------------------------------------------

// Appends one JSON object per line, matching the Python EventPublisher schema:
//   {"timestamp":..., "source":..., "event_type":..., "details":{...}}
//
// `details` is passed pre-rendered (already-escaped key/value pairs) so that
// callers stay allocation-light on the hot path.
class JsonLogger {
public:
    JsonLogger(std::string source, std::string path)
        : source_(std::move(source)), path_(std::move(path)) {}

    void set_path(const std::string &path) {
        std::lock_guard<std::mutex> guard(mutex_);
        path_ = path;
    }

    void event(const std::string &event_type, const std::string &details_json) {
        std::string line = "{\"timestamp\":\"" + now_utc_iso() +
                           "\",\"source\":\"" + json_escape(source_) +
                           "\",\"event_type\":\"" + json_escape(event_type) +
                           "\",\"details\":{" + details_json + "}}";
        std::lock_guard<std::mutex> guard(mutex_);
        // stdout so the controller's per-component log captures it too.
        std::fprintf(stdout, "%s\n", line.c_str());
        std::fflush(stdout);
        if (path_.empty()) {
            return;
        }
        std::FILE *f = std::fopen(path_.c_str(), "a");
        if (f == nullptr) {
            // The log directory usually just does not exist yet (a fresh
            // runtime/ tree). Create it lazily and retry once, so events are
            // never silently dropped on first start.
            if (!make_parent_dirs(path_)) {
                return;  // never fail a session because logging is unavailable
            }
            f = std::fopen(path_.c_str(), "a");
            if (f == nullptr) {
                return;
            }
        }
        std::fprintf(f, "%s\n", line.c_str());
        std::fclose(f);
    }

private:
    std::string source_;
    std::string path_;
    std::mutex mutex_;
};

// Build a `"key":"value"` pair with the value escaped.
inline std::string jstr(const std::string &key, const std::string &value) {
    return "\"" + json_escape(key) + "\":\"" + json_escape(value) + "\"";
}

// Build a `"key":number` pair.
inline std::string jnum(const std::string &key, long long value) {
    return "\"" + json_escape(key) + "\":" + std::to_string(value);
}

inline std::string jjoin(const std::vector<std::string> &parts) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out += ",";
        }
        out += parts[i];
    }
    return out;
}

// --------------------------------------------------------------------------
// Socket helpers
// --------------------------------------------------------------------------

// Write the whole buffer, retrying on partial writes and EINTR.
// Returns true only when every byte has been handed to the kernel.
inline bool send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline bool send_all(int fd, const std::string &s) {
    return send_all(fd, reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

// Apply a receive timeout so a silent peer cannot hold a slot forever.
inline bool set_recv_timeout(int fd, double seconds) {
    struct timeval tv;
    tv.tv_sec = static_cast<time_t>(seconds);
    tv.tv_usec = static_cast<suseconds_t>((seconds - static_cast<double>(tv.tv_sec)) * 1e6);
    return ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

inline bool set_send_timeout(int fd, double seconds) {
    struct timeval tv;
    tv.tv_sec = static_cast<time_t>(seconds);
    tv.tv_usec = static_cast<suseconds_t>((seconds - static_cast<double>(tv.tv_sec)) * 1e6);
    return ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
}

// True when recv() returned -1 because the receive timeout expired.
inline bool recv_timed_out() {
    return errno == EAGAIN || errno == EWOULDBLOCK;
}

// Create, bind and listen on an IPv4 socket. Returns -1 and fills `error` on
// failure. Binding to a loopback address requires no privileges, and ports
// >= 1024 avoid the need for root entirely.
inline int create_listener(const std::string &bind_addr, uint16_t port, int backlog,
                           std::string &error) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        error = std::string("socket: ") + std::strerror(errno);
        return -1;
    }

    int opt = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        error = std::string("setsockopt(SO_REUSEADDR): ") + std::strerror(errno);
        ::close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr) != 1) {
        error = "invalid bind address: " + bind_addr;
        ::close(fd);
        return -1;
    }

    if (::bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
        error = std::string("bind ") + bind_addr + ":" + std::to_string(port) + ": " +
                std::strerror(errno);
        ::close(fd);
        return -1;
    }
    if (::listen(fd, backlog) != 0) {
        error = std::string("listen: ") + std::strerror(errno);
        ::close(fd);
        return -1;
    }
    return fd;
}

// Thread-safe peer address formatting (inet_ntoa is not reentrant).
inline std::string peer_ip(const struct sockaddr_in &addr) {
    char buf[INET_ADDRSTRLEN];
    if (::inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf)) == nullptr) {
        return "0.0.0.0";
    }
    return std::string(buf);
}

// --------------------------------------------------------------------------
// Argument parsing helpers
// --------------------------------------------------------------------------

// Parse a non-negative integer within [min_value, max_value]. Returns false on
// trailing garbage, empty input or a range violation.
inline bool parse_int_arg(const char *text, long min_value, long max_value, long &out) {
    if (text == nullptr || *text == '\0') {
        return false;
    }
    char *end = nullptr;
    errno = 0;
    long value = std::strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    if (value < min_value || value > max_value) {
        return false;
    }
    out = value;
    return true;
}

}  // namespace icsd

#endif  // ICS_DECEPTION_NET_UTIL_H
