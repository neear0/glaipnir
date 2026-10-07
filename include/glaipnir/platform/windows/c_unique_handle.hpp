#pragma once

namespace glaipnir::platform::windows {

class c_unique_handle {
public:
    c_unique_handle() noexcept = default;
    explicit c_unique_handle(void* handle) noexcept : handle_(handle) {}
    ~c_unique_handle() { reset(); }

    c_unique_handle(c_unique_handle&& other) noexcept : handle_(other.release()) {}
    c_unique_handle& operator=(c_unique_handle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    c_unique_handle(const c_unique_handle&) = delete;
    c_unique_handle& operator=(const c_unique_handle&) = delete;

    void* get() const noexcept { return handle_; }
    void* release() noexcept {
        void* handle = handle_;
        handle_ = nullptr;
        return handle;
    }
    void reset(void* handle = nullptr) noexcept;
    bool valid() const noexcept;

private:
    void* handle_ = nullptr;
};

}
