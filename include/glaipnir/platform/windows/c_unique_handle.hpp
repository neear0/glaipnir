#pragma once

namespace glaipnir::platform::windows {

/// Owning wrapper for a Win32 kernel HANDLE.
///
/// Declared with `void*` so public headers do not drag in <windows.h>.
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

    /// The raw handle; ownership stays here.
    void* get() const noexcept { return handle_; }
    /// Gives up ownership without closing.
    void* release() noexcept {
        void* handle = handle_;
        handle_ = nullptr;
        return handle;
    }
    /// Closes the current handle (if any) and adopts `handle`.
    void reset(void* handle = nullptr) noexcept;
    /// True for anything other than NULL and INVALID_HANDLE_VALUE.
    bool valid() const noexcept;

private:
    void* handle_ = nullptr;
};

} // namespace glaipnir::platform::windows
