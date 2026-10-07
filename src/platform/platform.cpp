#include "glaipnir/platform/platform.hpp"

#include <utility>

#include "glaipnir/core/path_util.hpp"

#ifdef _WIN32
#include "platform/windows/detail/win_util.hpp"
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

using glaipnir::core::error_code;
using glaipnir::core::result_t;

result_t<glaipnir::platform::c_session_lock> glaipnir::platform::c_session_lock::acquire(const std::filesystem::path& path) {
#ifdef _WIN32
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD code = GetLastError();
        if (code == ERROR_SHARING_VIOLATION) {
            return core::make_error(error_code::busy, "session is in use by another glaipnir process");
        }
        return windows::detail::win32_error("cannot lock " + core::to_display_string(path), code);
    }
    return c_session_lock{reinterpret_cast<std::intptr_t>(handle)};
#else
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        return core::make_error(error_code::io_error, "cannot open lock " + core::to_display_string(path), errno);
    }
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        ::close(fd);
        return core::make_error(error_code::busy, "session is in use by another glaipnir process");
    }
    return c_session_lock{fd};
#endif
}

glaipnir::platform::c_session_lock::c_session_lock(c_session_lock&& other) noexcept
    : native_(std::exchange(other.native_, -1)) {}

glaipnir::platform::c_session_lock& glaipnir::platform::c_session_lock::operator=(c_session_lock&& other) noexcept {
    if (this != &other) {
        release();
        native_ = std::exchange(other.native_, -1);
    }
    return *this;
}

glaipnir::platform::c_session_lock::~c_session_lock() {
    release();
}

void glaipnir::platform::c_session_lock::release() noexcept {
    if (native_ == -1) {
        return;
    }
#ifdef _WIN32
    CloseHandle(reinterpret_cast<HANDLE>(native_));
#else
    ::close(static_cast<int>(native_));
#endif
    native_ = -1;
}

std::filesystem::path glaipnir::platform::default_state_root() {
    if (const auto overridden = core::host_env("GLAIPNIR_STATE_DIR"); !overridden.empty()) {
        return core::from_utf8(overridden);
    }
#ifdef _WIN32
    return core::from_utf8(core::host_env("LOCALAPPDATA")) / "glaipnir";
#else
    if (const auto xdg = core::host_env("XDG_STATE_HOME"); !xdg.empty()) {
        return core::from_utf8(xdg) / "glaipnir";
    }
    return core::from_utf8(core::host_env("HOME")) / ".local" / "state" / "glaipnir";
#endif
}

#ifdef _WIN32

result_t<void> glaipnir::platform::cleanup_session(std::string_view session_id, const std::filesystem::path& session_dir) {
    return platform_backend::cleanup(session_id, session_dir);
}

result_t<void> glaipnir::platform::pause_session(std::string_view session_id) {
    return platform_backend::pause_running(session_id);
}

result_t<void> glaipnir::platform::resume_session(std::string_view session_id) {
    return platform_backend::resume_running(session_id);
}

result_t<void> glaipnir::platform::terminate_session(std::string_view session_id) {
    return platform_backend::terminate_running(session_id);
}

#else

result_t<void> glaipnir::platform::cleanup_session(std::string_view, const std::filesystem::path&) {
    return core::ok();
}

result_t<void> glaipnir::platform::pause_session(std::string_view) {
    return core::make_error(error_code::not_supported, "pause is not implemented on this platform yet");
}

result_t<void> glaipnir::platform::resume_session(std::string_view) {
    return core::make_error(error_code::not_supported, "resume is not implemented on this platform yet");
}

result_t<void> glaipnir::platform::terminate_session(std::string_view) {
    return core::make_error(error_code::not_supported, "terminate is not implemented on this platform yet");
}

#endif
