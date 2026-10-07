#pragma once

#include <cstdint>
#include <filesystem>
#include <string_view>

#include "glaipnir/core/error.hpp"

#ifdef _WIN32
#include "glaipnir/platform/windows/c_windows_backend.hpp"
#endif

namespace glaipnir::platform {

#ifdef _WIN32
/// Isolation backend for this build. Chosen at compile time: there is exactly one per OS today,
/// so a virtual interface would add indirection without adding choice.
using platform_backend = windows::c_windows_backend;
#endif

/// Exclusive, crash-safe lock on a session. Released when the object is destroyed or the
/// process dies, so a crashed run never leaves a session permanently "busy".
class c_session_lock {
public:
    /// Acquires the lock file at `path` without waiting. Fails with `busy` if someone holds it.
    static core::result_t<c_session_lock> acquire(const std::filesystem::path& path);

    c_session_lock(c_session_lock&& other) noexcept;
    c_session_lock& operator=(c_session_lock&& other) noexcept;
    c_session_lock(const c_session_lock&) = delete;
    c_session_lock& operator=(const c_session_lock&) = delete;
    ~c_session_lock();

private:
    explicit c_session_lock(std::intptr_t native) : native_(native) {}
    void release() noexcept;

    std::intptr_t native_ = -1; ///< HANDLE on Windows, file descriptor elsewhere
};

/// Default state directory: %LOCALAPPDATA%\glaipnir on Windows, $XDG_STATE_HOME/glaipnir
/// (or ~/.local/state/glaipnir) elsewhere. GLAIPNIR_STATE_DIR overrides both.
std::filesystem::path default_state_root();

/// Removes platform resources tied to a session (grants, container profiles).
core::result_t<void> cleanup_session(std::string_view session_id, const std::filesystem::path& session_dir);

/// Controls a session that is running in another process.
core::result_t<void> pause_session(std::string_view session_id);
core::result_t<void> resume_session(std::string_view session_id);
core::result_t<void> terminate_session(std::string_view session_id);

} // namespace glaipnir::platform
