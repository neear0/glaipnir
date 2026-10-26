#pragma once
#include "harness/core/types.hpp"
#include <Windows.h>
#include <stdexcept>

namespace harness {
class c_handle {
public:
    explicit c_handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~c_handle() { if (valid()) CloseHandle(value_); }
    c_handle(const c_handle&) = delete;
    c_handle& operator=(const c_handle&) = delete;
    c_handle(c_handle&& other) noexcept : value_(other.release()) {}
    c_handle& operator=(c_handle&& other) noexcept {
        if (this != &other) { if (valid()) CloseHandle(value_); value_ = other.release(); }
        return *this;
    }
    HANDLE get() const noexcept { return value_; }
    HANDLE release() noexcept { HANDLE result = value_; value_ = nullptr; return result; }
    bool valid() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
private:
    HANDLE value_;
};
void check_win(bool success, const char* operation);
std::wstring quote_argument(const std::wstring& value);
}
