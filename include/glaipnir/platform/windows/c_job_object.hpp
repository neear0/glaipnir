#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/platform/windows/c_unique_handle.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::platform::windows {

/// Accounting snapshot of a job.
struct job_usage_t {
    std::chrono::milliseconds user_time{0};
    std::chrono::milliseconds kernel_time{0};
    std::uint64_t peak_memory_bytes = 0;
    std::uint32_t active_processes = 0;
};

/// Job Object holding an entire sandboxed process tree.
///
/// Processes are placed in the job at creation time and cannot break away, so every child an
/// agent spawns (git, node, python, ...) inherits the same limits and dies with the job.
class c_job_object {
public:
    /// Creates a named job (`Local\glaipnir.job.<session_id>`) with limits from the policy.
    /// Fails with `busy` if a job of that name already exists (a run is in progress).
    static core::result_t<c_job_object> create(std::string_view session_id, const policy::resource_limit_t& limits,
                                               const policy::capability_t& capabilities);

    /// Opens the job of a running session from another process (for pause/resume/terminate).
    static core::result_t<c_job_object> open(std::string_view session_id);

    /// Raw job HANDLE.
    void* handle() const noexcept { return handle_.get(); }

    /// Kills every process in the job.
    core::result_t<void> terminate(unsigned exit_code) const;

    /// Suspends every thread of every process in the job.
    core::result_t<void> suspend() const;

    /// Resumes threads previously suspended by suspend().
    core::result_t<void> resume() const;

    /// Current accounting figures.
    core::result_t<job_usage_t> usage() const;

    /// IDs of processes currently in the job.
    core::result_t<std::vector<std::uint32_t>> process_ids() const;

private:
    explicit c_job_object(c_unique_handle handle) : handle_(std::move(handle)) {}

    c_unique_handle handle_;
};

} // namespace glaipnir::platform::windows
