#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glaipnir::isolation {

/// Why a sandboxed run ended.
enum class termination_reason {
    exited,       ///< root process exited on its own
    wall_timeout, ///< limits.wall_timeout_s elapsed
    cpu_timeout,  ///< limits.cpu_timeout_s of CPU time consumed
    terminated,   ///< stopped through terminate()
};

/// Outcome of one sandboxed run.
struct sandbox_result_t {
    int exit_code = -1;
    termination_reason reason = termination_reason::exited;
    std::chrono::milliseconds wall_time{0};
    std::chrono::milliseconds cpu_time{0};
    std::uint64_t peak_memory_bytes = 0;
};

/// What to execute inside an already-prepared sandbox.
struct launch_spec_t {
    std::vector<std::string> argv;
    std::filesystem::path working_directory;
    /// Complete environment from the policy. Backends add only platform essentials
    /// (e.g. SystemRoot) and sandbox-private TEMP/HOME; the host environment is never inherited.
    std::vector<std::pair<std::string, std::string>> environment;
};

std::string_view to_string(termination_reason reason) noexcept;

} // namespace glaipnir::isolation
