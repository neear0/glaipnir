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

class c_windows_backend {
public:
    static core::result_t<c_windows_backend> prepare(const policy::c_policy& policy, std::string_view session_id,
                                                     const std::filesystem::path& session_dir,
                                                     const std::filesystem::path& workspace, core::c_audit_log& audit);

    core::result_t<void> start(const isolation::launch_spec_t& spec);

    core::result_t<isolation::sandbox_result_t> wait();

    core::result_t<void> pause() const;
    core::result_t<void> resume() const;

    core::result_t<void> terminate() const;

    static core::result_t<void> cleanup(std::string_view session_id, const std::filesystem::path& session_dir);

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

}
