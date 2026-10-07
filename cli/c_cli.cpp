#include "c_cli.hpp"

#include <cstdio>
#include <format>
#include <iostream>
#include <optional>
#include <random>

#include "glaipnir/core/c_audit_log.hpp"
#include "glaipnir/core/c_sandbox.hpp"
#include "glaipnir/core/c_session.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/platform/platform.hpp"
#include "glaipnir/policy/c_policy.hpp"
#include "glaipnir/version.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace glaipnir::cli {

namespace fs = std::filesystem;
using core::open_mode;

namespace {

constexpr std::string_view usage_text = R"(glaipnir - deny-by-default sandbox for AI agents

usage:
  glaipnir run [--policy FILE] [--session ID] [--cwd DIR] -- COMMAND [ARGS...]
  glaipnir policy check FILE
  glaipnir session list
  glaipnir session create|delete|pause|resume|kill ID
  glaipnir session fork SOURCE_ID NEW_ID
  glaipnir snapshot list SESSION
  glaipnir snapshot create|rollback|delete SESSION LABEL
  glaipnir audit verify SESSION
  glaipnir version

global options:
  --state-dir DIR   where sessions, snapshots and audit logs live
                    (default: %LOCALAPPDATA%\glaipnir, or $GLAIPNIR_STATE_DIR)

Without --policy the sandbox gets nothing: no paths beyond its workspace, no network,
no inherited environment, no child processes. Without --session the run uses a throwaway
session that is deleted afterwards.
)";

void print_error(const core::error_t& error) {
    std::cerr << "glaipnir: " << core::describe(error) << "\n";
}

int fail(const core::error_t& error) {
    print_error(error);
    return exit_internal;
}

int usage_error(std::string_view message) {
    std::cerr << "glaipnir: " << message << "\n(run `glaipnir help` for usage)\n";
    return exit_usage;
}

std::string random_suffix() {
    std::random_device device;
    return std::format("{:08x}", device());
}

#ifdef _WIN32
// The sandboxed process shares our console and receives Ctrl+C itself; glaipnir must stay
// alive to report the result and tear the job down, so it ignores the signal.
BOOL WINAPI ignore_ctrl_c(DWORD type) {
    return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ? TRUE : FALSE;
}
#endif

} // namespace

c_cli::c_cli(std::vector<std::string> args) : args_(std::move(args)) {}

int c_cli::execute() {
    // Pull out global options that may appear before the command separator.
    std::vector<std::string> remaining;
    std::optional<fs::path> state_dir;
    for (std::size_t i = 0; i < args_.size(); ++i) {
        if (args_[i] == "--") {
            remaining.insert(remaining.end(), args_.begin() + static_cast<std::ptrdiff_t>(i), args_.end());
            break;
        }
        if (args_[i] == "--state-dir") {
            if (i + 1 >= args_.size()) {
                return usage_error("--state-dir needs a value");
            }
            state_dir = core::from_utf8(args_[++i]);
            continue;
        }
        remaining.push_back(args_[i]);
    }
    args_ = std::move(remaining);
    state_root_ = state_dir ? fs::absolute(*state_dir) : platform::default_state_root();

    if (args_.empty() || args_[0] == "help" || args_[0] == "--help" || args_[0] == "-h") {
        std::cout << usage_text;
        return args_.empty() ? exit_usage : 0;
    }
    const auto& command = args_[0];
    if (command == "version" || command == "--version") {
        std::cout << "glaipnir " << version_string << "\n";
        return 0;
    }
    if (command == "run") {
        return command_run();
    }
    if (command == "policy") {
        return command_policy();
    }
    if (command == "session") {
        return command_session();
    }
    if (command == "snapshot") {
        return command_snapshot();
    }
    if (command == "audit") {
        return command_audit();
    }
    return usage_error("unknown command '" + command + "'");
}

int c_cli::command_run() {
    std::optional<fs::path> policy_file;
    std::string session_id;
    fs::path working_directory;
    std::vector<std::string> command;
    for (std::size_t i = 1; i < args_.size(); ++i) {
        const auto& arg = args_[i];
        if (arg == "--") {
            command.assign(args_.begin() + static_cast<std::ptrdiff_t>(i) + 1, args_.end());
            break;
        }
        if (i + 1 >= args_.size()) {
            return usage_error("option " + arg + " needs a value (and the command must follow `--`)");
        }
        if (arg == "--policy") {
            policy_file = core::from_utf8(args_[++i]);
        } else if (arg == "--session") {
            session_id = args_[++i];
        } else if (arg == "--cwd") {
            working_directory = core::from_utf8(args_[++i]);
        } else {
            return usage_error("unknown run option '" + arg + "'");
        }
    }
    if (command.empty()) {
        return usage_error("run needs a command after `--`");
    }

    const auto host = policy::host_context_t::detect(state_root_);
    auto policy = policy_file ? policy::c_policy::load_file(*policy_file, host)
                              : core::result_t<policy::c_policy>{policy::c_policy::deny_all()};
    if (!policy) {
        return fail(policy.error());
    }
    if (policy->data().network == policy::network_mode::unrestricted) {
        std::cerr << "glaipnir: warning: network.mode = \"unrestricted\" gives the sandbox direct internet access\n";
    }

    const bool ephemeral = session_id.empty();
    persistence::session_config_t config{ephemeral ? "tmp-" + random_suffix() : session_id, state_root_, ephemeral};

    int exit_code = exit_internal;
    {
        auto session = core::c_session::open(config, ephemeral ? open_mode::create : open_mode::open_or_create);
        if (!session) {
            return fail(session.error());
        }
        auto sandbox = core::c_sandbox::create(std::move(*policy), *session);
        if (!sandbox) {
            print_error(sandbox.error());
        } else {
#ifdef _WIN32
            SetConsoleCtrlHandler(ignore_ctrl_c, TRUE);
#endif
            auto result = sandbox->run(command, working_directory);
#ifdef _WIN32
            SetConsoleCtrlHandler(ignore_ctrl_c, FALSE);
#endif
            if (!result) {
                print_error(result.error());
            } else {
                exit_code = result->exit_code;
                if (result->reason == isolation::termination_reason::wall_timeout ||
                    result->reason == isolation::termination_reason::cpu_timeout) {
                    std::cerr << "glaipnir: killed: " << isolation::to_string(result->reason) << "\n";
                    exit_code = exit_timeout;
                }
            }
        }
    }
    if (ephemeral) {
        if (auto destroyed = core::c_session::destroy(state_root_, config.session_id); !destroyed) {
            std::cerr << "glaipnir: warning: cleanup of ephemeral session failed: " << core::describe(destroyed.error()) << "\n";
        }
    }
    return exit_code;
}

int c_cli::command_policy() {
    if (args_.size() != 3 || args_[1] != "check") {
        return usage_error("usage: glaipnir policy check FILE");
    }
    auto policy = policy::c_policy::load_file(core::from_utf8(args_[2]), policy::host_context_t::detect(state_root_));
    if (!policy) {
        return fail(policy.error());
    }
    std::cout << "# policy is valid; normalized form (digest " << policy->digest() << ")\n\n" << policy->to_toml();
    return 0;
}

int c_cli::command_session() {
    if (args_.size() < 2) {
        return usage_error("usage: glaipnir session list|create|delete|fork|pause|resume|kill ...");
    }
    const auto& action = args_[1];
    if (action == "list" && args_.size() == 2) {
        auto ids = core::c_session::list(state_root_);
        if (!ids) {
            return fail(ids.error());
        }
        for (const auto& id : *ids) {
            std::cout << id << "\n";
        }
        return 0;
    }
    if (action == "fork" && args_.size() == 4) {
        auto source = core::c_session::open({args_[2], state_root_, false}, open_mode::open_existing);
        if (!source) {
            return fail(source.error());
        }
        auto child = source->fork_session(args_[3]);
        if (!child) {
            return fail(child.error());
        }
        std::cout << "forked " << args_[2] << " -> " << args_[3] << "\n";
        return 0;
    }
    if (args_.size() != 3) {
        return usage_error("usage: glaipnir session " + action + " ID");
    }
    const auto& id = args_[2];
    core::result_t<void> outcome = core::ok();
    if (action == "create") {
        auto session = core::c_session::open({id, state_root_, false}, open_mode::create);
        outcome = session ? core::ok() : core::result_t<void>{session.error()};
    } else if (action == "delete") {
        outcome = core::c_session::destroy(state_root_, id);
    } else if (action == "pause") {
        outcome = platform::pause_session(id);
    } else if (action == "resume") {
        outcome = platform::resume_session(id);
    } else if (action == "kill") {
        outcome = platform::terminate_session(id);
    } else {
        return usage_error("unknown session action '" + action + "'");
    }
    if (!outcome) {
        return fail(outcome.error());
    }
    std::cout << action << ": " << id << "\n";
    return 0;
}

int c_cli::command_snapshot() {
    if (args_.size() < 3) {
        return usage_error("usage: glaipnir snapshot list|create|rollback|delete SESSION [LABEL]");
    }
    const auto& action = args_[1];
    auto session = core::c_session::open({args_[2], state_root_, false}, open_mode::open_existing);
    if (!session) {
        return fail(session.error());
    }
    if (action == "list" && args_.size() == 3) {
        auto snapshots = session->snapshots();
        if (!snapshots) {
            return fail(snapshots.error());
        }
        for (const auto& meta : *snapshots) {
            std::cout << std::format("{:<24} {}  {:>8} files  {:>12} bytes\n", meta.snapshot.label,
                                     meta.snapshot.created_at, meta.snapshot.files, meta.snapshot.bytes);
        }
        return 0;
    }
    if (args_.size() != 4) {
        return usage_error("usage: glaipnir snapshot " + action + " SESSION LABEL");
    }
    const auto& label = args_[3];
    if (action == "create") {
        auto meta = session->snapshot(label);
        if (!meta) {
            return fail(meta.error());
        }
        std::cout << std::format("snapshot {}: {} files, {} bytes\n", label, meta->snapshot.files, meta->snapshot.bytes);
        if (meta->snapshot.skipped_links != 0) {
            std::cerr << std::format("glaipnir: note: {} symlinks/junctions in the workspace were not captured\n",
                                     meta->snapshot.skipped_links);
        }
        return 0;
    }
    core::result_t<void> outcome = core::ok();
    if (action == "rollback") {
        outcome = session->rollback(label);
    } else if (action == "delete") {
        outcome = session->remove_snapshot(label);
    } else {
        return usage_error("unknown snapshot action '" + action + "'");
    }
    if (!outcome) {
        return fail(outcome.error());
    }
    std::cout << action << ": " << label << "\n";
    return 0;
}

int c_cli::command_audit() {
    if (args_.size() != 3 || args_[1] != "verify") {
        return usage_error("usage: glaipnir audit verify SESSION");
    }
    auto count = core::c_audit_log::verify(core::c_session::audit_path_for(state_root_, args_[2]));
    if (!count) {
        return fail(count.error());
    }
    std::cout << "audit log intact: " << *count << " records\n";
    return 0;
}

} // namespace glaipnir::cli
