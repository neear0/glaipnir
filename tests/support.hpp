#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include "harness/core/runtime.hpp"
#include <iostream>

namespace harness::tests {
inline void require(bool value, const std::string& text) { if (!value) throw std::runtime_error(text); }
template<class c_function> void expect_error(c_function function, const std::string& text) {
    bool failed = false; try { function(); } catch (const std::exception&) { failed = true; } require(failed, text);
}
struct response_t { int status; json_t body; std::string raw; int delay_ms = 0; };
class c_socket {
public:
    explicit c_socket(SOCKET socket = INVALID_SOCKET) : socket_(socket) {}
    ~c_socket() { if (socket_ != INVALID_SOCKET) closesocket(socket_); }
    SOCKET get() const { return socket_; }
    c_socket(const c_socket&) = delete;
    c_socket& operator=(const c_socket&) = delete;
private:
    SOCKET socket_;
};
class c_http_fixture {
public:
    explicit c_http_fixture(std::vector<response_t> responses);
    ~c_http_fixture();
    std::string endpoint(const std::string& path = "/model") const;
    void finish();
    std::vector<json_t> requests;
    std::vector<std::string> headers;
private:
    c_socket listener_;
    unsigned short port_ = 0;
    std::exception_ptr error_;
    std::jthread server_;
};
}
