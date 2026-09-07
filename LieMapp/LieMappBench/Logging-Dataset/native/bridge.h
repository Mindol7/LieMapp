#pragma once

#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

// This transport does not write logs or evidence files. logger.py owns storage.
namespace liemapp {
using json = nlohmann::ordered_json;

inline bool enabled() {
    const char * path = std::getenv("LIEMAPP_SOCKET");
    return path && *path;
}

inline std::string base64(const std::vector<unsigned char> & bytes) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(4 * ((bytes.size() + 2) / 3));
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const uint32_t value = (uint32_t(bytes[i]) << 16)
            | (i + 1 < bytes.size() ? uint32_t(bytes[i + 1]) << 8 : 0)
            | (i + 2 < bytes.size() ? uint32_t(bytes[i + 2]) : 0);
        output.push_back(alphabet[(value >> 18) & 63]);
        output.push_back(alphabet[(value >> 12) & 63]);
        output.push_back(i + 1 < bytes.size() ? alphabet[(value >> 6) & 63] : '=');
        output.push_back(i + 2 < bytes.size() ? alphabet[value & 63] : '=');
    }
    return output;
}

inline json tensor(const char * name, const float * values, size_t count, const std::vector<size_t> & shape) {
    static_assert(sizeof(float) == 4 && std::numeric_limits<float>::is_iec559, "IEEE float32 required");
    size_t shape_count = 1;
    for (size_t dim : shape) {
        if (dim != 0 && shape_count > std::numeric_limits<size_t>::max() / dim) {
            throw std::runtime_error("LieMapp tensor shape overflow");
        }
        shape_count *= dim;
    }
    if (shape_count != count || (count && !values) || count > 12000000) {
        throw std::runtime_error("LieMapp tensor size mismatch or message limit");
    }
    std::vector<unsigned char> bytes(count * 4);
    for (size_t i = 0; i < count; ++i) {
        uint32_t bits;
        std::memcpy(&bits, values + i, 4);
        for (unsigned j = 0; j < 4; ++j) {
            bytes[4 * i + j] = static_cast<unsigned char>(bits >> (8 * j));
        }
    }
    return {{"name", name}, {"dtype", "float32"}, {"shape", shape}, {"data_base64", base64(bytes)}};
}

struct socket_handle {
    int fd;
    explicit socket_handle(int value) : fd(value) {}
    ~socket_handle() { if (fd >= 0) { ::close(fd); } }
    socket_handle(const socket_handle &) = delete;
    socket_handle & operator=(const socket_handle &) = delete;
};

inline void emit(const char * stage, const char * path, const char * function, int line,
                 const char * point_id, json raw, const std::string & summary,
                 json tensors = json::array()) {
    if (!enabled()) {
        return;
    }
    const char * socket_path = std::getenv("LIEMAPP_SOCKET");
    const char * context_text = std::getenv("LIEMAPP_CONTEXT_JSON");
    json context = context_text ? json::parse(context_text) : json::object();
    json payload = {
        {"stage", stage},
        {"source", {{"path", path}, {"function", function}, {"line", line}, {"logging_point_id", point_id}}},
        {"context", context}, {"raw", std::move(raw)},
        {"readable", {{"summary", summary}}}, {"tensors", std::move(tensors)},
    };
    std::string message = payload.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
    if (message.size() > 64 * 1024 * 1024) {
        throw std::runtime_error("LieMapp message exceeds 64 MiB");
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (std::strlen(socket_path) >= sizeof(address.sun_path)) {
        throw std::runtime_error("LieMapp socket path too long");
    }
    std::strcpy(address.sun_path, socket_path);
    socket_handle handle(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (handle.fd < 0) {
        throw std::runtime_error("LieMapp socket creation failed");
    }
    timeval timeout{30, 0};
    if (::setsockopt(handle.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0
            || ::setsockopt(handle.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0
            || ::connect(handle.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
        throw std::runtime_error("LieMapp collector connection failed");
    }
    size_t sent = 0;
    while (sent < message.size()) {
        const ssize_t n = ::send(handle.fd, message.data() + sent, message.size() - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            throw std::runtime_error("LieMapp collector send failed");
        }
        sent += size_t(n);
    }
    std::string reply;
    char buffer[1024];
    while (reply.find('\n') == std::string::npos && reply.size() < 65536) {
        const ssize_t n = ::recv(handle.fd, buffer, sizeof(buffer), 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            throw std::runtime_error("LieMapp collector acknowledgement missing");
        }
        reply.append(buffer, size_t(n));
    }
    auto acknowledgement = json::parse(reply.substr(0, reply.find('\n')));
    if (!acknowledgement.value("ok", false)) {
        throw std::runtime_error("LieMapp collector rejected event: " + reply);
    }
}
} // namespace liemapp
