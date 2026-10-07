#include "win_util.hpp"

#include "glaipnir/platform/windows/c_unique_handle.hpp"

namespace glaipnir::platform::windows {

void c_unique_handle::reset(void* handle) noexcept {
    if (valid()) {
        CloseHandle(handle_);
    }
    handle_ = handle;
}

bool c_unique_handle::valid() const noexcept {
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
}

std::wstring to_wide(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
    return wide;
}

std::string from_wide(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string narrow(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), narrow.data(), size, nullptr, nullptr);
    return narrow;
}

std::string win32_message(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                            FORMAT_MESSAGE_IGNORE_INSERTS,
                                        nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::string message = length == 0 ? "unknown error" : from_wide(std::wstring_view{buffer, length});
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r' || message.back() == ' ' ||
                                message.back() == '.')) {
        message.pop_back();
    }
    return message;
}

core::error_t last_error(std::string_view what, core::error_code code) {
    return win32_error(what, GetLastError(), code);
}

core::error_t win32_error(std::string_view what, DWORD code, core::error_code category) {
    if (code == ERROR_ACCESS_DENIED && category == core::error_code::platform_error) {
        category = core::error_code::permission_denied;
    }
    return core::make_error(category, std::string{what} + ": " + win32_message(code), static_cast<long>(code));
}

} // namespace glaipnir::platform::windows
