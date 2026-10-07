#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "glaipnir/core/c_session.hpp"
#include "glaipnir/core/error.hpp"
#include "glaipnir/isolation/isolation_types.hpp"
#include "glaipnir/platform/platform.hpp"
#include "glaipnir/policy/c_policy.hpp"

namespace glaipnir::core {

/// Main entry point: runs a command or long-lived agent under a policy, inside a session.
///
/// Typical use:
/// @code
///   auto session = c_session::open(config, open_mode::open_or_create);
///   auto sandbox = c_sandbox::create(policy, *session);
///   auto result  = sandbox->run({"python", "agent.py"});
/// @endcode
/// Isolation is (re)applied by create() every time, which is what makes restored snapshots and
/// forked sessions safe: they never carry permissions, only files.
class c_sandbox {
public:
    /// Applies the policy's isolation for `session`. The session must outlive the sandbox.
    static result_t<c_sandbox> create(policy::c_policy policy, c_session& session);

    /// Starts `argv` in the session workspace (or `working_directory`, which must be inside it).
    result_t<void> start(const std::vector<std::string>& argv, const std::filesystem::path& working_directory = {});

    /// Waits for the started command to finish and records the outcome in the audit log.
    result_t<isolation::sandbox_result_t> wait();

    /// start() followed by wait().
    result_t<isolation::sandbox_result_t> run(const std::vector<std::string>& argv,
                                              const std::filesystem::path& working_directory = {});

    /// Freezes every process in the sandbox (e.g. before a consistent snapshot).
    result_t<void> pause();
    /// Thaws a paused sandbox.
    result_t<void> resume();
    /// Kills the whole process tree. Thread-safe with respect to wait().
    result_t<void> terminate() const;

    const policy::c_policy& policy() const noexcept { return policy_; }

private:
    c_sandbox(policy::c_policy policy, c_session& session, platform::platform_backend backend);

    policy::c_policy policy_;
    c_session* session_;
    platform::platform_backend backend_;
};

} // namespace glaipnir::core
