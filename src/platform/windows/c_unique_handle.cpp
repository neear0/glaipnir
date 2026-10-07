#include "glaipnir/platform/windows/c_unique_handle.hpp"

#include "platform/windows/detail/win_util.hpp"

void glaipnir::platform::windows::c_unique_handle::reset(void* handle) noexcept {
    if (valid()) {
        CloseHandle(handle_);
    }
    handle_ = handle;
}

bool glaipnir::platform::windows::c_unique_handle::valid() const noexcept {
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
}
