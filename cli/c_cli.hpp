#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace glaipnir::cli {

/// Process exit codes used when glaipnir itself (not the sandboxed command) decides the outcome.
inline constexpr int exit_usage = 2;
inline constexpr int exit_timeout = 124;   ///< same as coreutils timeout(1)
inline constexpr int exit_internal = 125;  ///< same as docker run: the sandbox could not be set up

/// Command-line front end. Parses arguments, dispatches to the library, prints results.
class c_cli {
public:
    /// @param args UTF-8 arguments without the program name
    explicit c_cli(std::vector<std::string> args);

    /// Executes the command and returns the process exit code.
    int execute();

private:
    int command_run();
    int command_policy();
    int command_session();
    int command_snapshot();
    int command_audit();

    std::vector<std::string> args_;
    std::filesystem::path state_root_;
};

} // namespace glaipnir::cli
