#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "glaipnir/core/c_audit_log.hpp"
#include "glaipnir/core/error.hpp"
#include "glaipnir/isolation/isolation_types.hpp"
#include "glaipnir/platform/windows/c_app_container.hpp"
#include "glaipnir/platform/windows/c_job_object.hpp"
#include "glaipnir/platform/windows/c_unique_handle.hpp"
#include "glaipnir/policy/c_policy.hpp"

namespace glaipnir::platform::windows {

/// AppContainer + Job Object isolation backend. Works as a normal user on every Windows 10+
/// edition, including Home.
///
/// Translation of policy_t:
///  - identity:    per-session AppContainer SID (optionally LPAC); no capabilities unless the
///                 network policy needs one
///  - filesystem:  explicit DACL grants for the session SID on the workspace and policy paths,
///                 tracked in a ledger so stale grants are revoked even after a crash
///  - network:     none → no capability; unrestricted → internetClient (no LAN); proxy → refused
///                 until the loopback-exempt proxy path exists
///  - resources:   Job Object limits, UI restrictions, kill-on-close, no breakaway
///  - process:     mitigation policies, optional child-process block, explicit handle list
class c_windows_backend {
public:
    /// Sets up identity and filesystem grants for a session. Nothing runs yet.
    /// @param session_dir directory holding the session's ledger (never exposed to the sandbox)
    /// @param workspace   directory exposed read-write and used as the default working directory
    static core::result_t<c_windows_backend> prepare(const policy::c_policy& policy, std::string_view session_id,
                                                     const std::filesystem::path& session_dir,
                                                     const std::filesystem::path& workspace, core::c_audit_log& audit);

    /// Launches the root process inside a fresh Job Object.
    core::result_t<void> start(const isolation::launch_spec_t& spec);

    /// Blocks until the root process exits or the wall-clock limit hits, then kills whatever
    /// is left in the job.
    core::result_t<isolation::sandbox_result_t> wait();

    /// Freezes / thaws every process in the sandbox.
    core::result_t<void> pause() const;
    core::result_t<void> resume() const;

    /// Kills the whole process tree. Safe to call from another thread (e.g. a Ctrl+C handler).
    core::result_t<void> terminate() const;

    /// Revokes every recorded grant outside `session_dir` and deletes the AppContainer profile.
    static core::result_t<void> cleanup(std::string_view session_id, const std::filesystem::path& session_dir);

    /// Pause / resume / terminate a session running in another glaipnir process.
    static core::result_t<void> pause_running(std::string_view session_id);
    static core::result_t<void> resume_running(std::string_view session_id);
    static core::result_t<void> terminate_running(std::string_view session_id);

private:
    c_windows_backend(policy::policy_t policy, std::string session_id, c_app_container container,
                      std::filesystem::path workspace, std::filesystem::path container_folder);

    core::result_t<std::wstring> build_environment(const isolation::launch_spec_t& spec) const;

    policy::policy_t policy_;
    std::string session_id_;
    c_app_container container_;
    std::filesystem::path workspace_;
    std::filesystem::path container_folder_;
    std::optional<c_job_object> job_;
    c_unique_handle process_;
    std::chrono::steady_clock::time_point started_at_{};
    std::unique_ptr<std::atomic<bool>> terminated_ = std::make_unique<std::atomic<bool>>(false);
};

} // namespace glaipnir::platform::windows
