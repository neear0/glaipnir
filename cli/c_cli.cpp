#include "c_cli.hpp"

#include <format>
#include <iostream>
#include <optional>

#include "detail/cli_output.hpp"
#include "detail/console.hpp"
#include "glaipnir/core/c_audit_log.hpp"
#include "glaipnir/core/c_sandbox.hpp"
#include "glaipnir/core/c_session.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/platform/platform.hpp"
#include "glaipnir/policy/c_policy.hpp"
#include "glaipnir/version.hpp"

using glaipnir::core::open_mode;

glaipnir::cli::c_cli::c_cli(std::vector<std::string> args) : args_(std::move(args))
{
}

int glaipnir::cli::c_cli::execute()
{
	std::vector<std::string> remaining;
	std::optional<std::filesystem::path> state_dir;
	for (std::size_t i = 0; i < args_.size(); ++i)
	{
		if (args_[i] == "--")
		{
			remaining.insert(remaining.end(), args_.begin() + static_cast<std::ptrdiff_t>(i), args_.end());
			break;
		}
		if (args_[i] == "--state-dir")
		{
			if (i + 1 >= args_.size())
			{
				return detail::usage_error("--state-dir needs a value");
			}
			state_dir = core::from_utf8(args_[++i]);
			continue;
		}
		remaining.push_back(args_[i]);
	}
	args_ = std::move(remaining);
	state_root_ = state_dir ? std::filesystem::absolute(*state_dir) : platform::default_state_root();

	if (args_.empty() || args_[0] == "help" || args_[0] == "--help" || args_[0] == "-h")
	{
		std::cout << detail::usage_text;
		return args_.empty() ? exit_usage : 0;
	}
	const auto& command = args_[0];
	if (command == "version" || command == "--version")
	{
		std::cout << "glaipnir " << version_string << "\n";
		return 0;
	}
	if (command == "run")
	{
		return command_run();
	}
	if (command == "policy")
	{
		return command_policy();
	}
	if (command == "session")
	{
		return command_session();
	}
	if (command == "snapshot")
	{
		return command_snapshot();
	}
	if (command == "audit")
	{
		return command_audit();
	}
	return detail::usage_error("unknown command '" + command + "'");
}

int glaipnir::cli::c_cli::command_run()
{
	std::optional<std::filesystem::path> policy_file;
	std::string session_id;
	std::filesystem::path working_directory;
	std::vector<std::string> command;
	for (std::size_t i = 1; i < args_.size(); ++i)
	{
		const auto& arg = args_[i];
		if (arg == "--")
		{
			command.assign(args_.begin() + static_cast<std::ptrdiff_t>(i) + 1, args_.end());
			break;
		}
		if (i + 1 >= args_.size())
		{
			return detail::usage_error("option " + arg + " needs a value (and the command must follow `--`)");
		}
		if (arg == "--policy")
		{
			policy_file = core::from_utf8(args_[++i]);
		}
		else if (arg == "--session")
		{
			session_id = args_[++i];
		}
		else if (arg == "--cwd")
		{
			working_directory = core::from_utf8(args_[++i]);
		}
		else
		{
			return detail::usage_error("unknown run option '" + arg + "'");
		}
	}
	if (command.empty())
	{
		return detail::usage_error("run needs a command after `--`");
	}

	const auto host = policy::host_context_t::detect(state_root_);
	auto policy = policy_file
		              ? policy::c_policy::load_file(*policy_file, host)
		              : core::result_t<policy::c_policy>{policy::c_policy::deny_all()};
	if (!policy)
	{
		return detail::fail(policy.error());
	}
	if (policy->data().network == policy::network_mode::unrestricted)
	{
		std::cerr << "glaipnir: warning: network.mode = \"unrestricted\" gives the sandbox direct internet access\n";
	}

	const bool ephemeral = session_id.empty();
	persistence::session_config_t config{
		ephemeral ? "tmp-" + detail::random_suffix() : session_id, state_root_, ephemeral
	};

	int exit_code = exit_internal;
	{
		auto session = core::c_session::open(config, ephemeral ? open_mode::create : open_mode::open_or_create);
		if (!session)
		{
			return detail::fail(session.error());
		}
		auto sandbox = core::c_sandbox::create(std::move(*policy), *session);
		if (!sandbox)
		{
			detail::print_error(sandbox.error());
		}
		else
		{
			for (const auto& notice : sandbox->notices())
			{
				std::cerr << "glaipnir: note: " << notice << "\n";
			}
			detail::ignore_interrupts(true);
			auto result = sandbox->run(command, working_directory);
			detail::ignore_interrupts(false);
			if (!result)
			{
				detail::print_error(result.error());
			}
			else
			{
				exit_code = result->exit_code;
				if (result->reason == isolation::termination_reason::wall_timeout ||
					result->reason == isolation::termination_reason::cpu_timeout)
				{
					std::cerr << "glaipnir: killed: " << isolation::to_string(result->reason) << "\n";
					exit_code = exit_timeout;
				}
			}
		}
	}
	if (ephemeral)
	{
		if (auto destroyed = core::c_session::destroy(state_root_, config.session_id); !destroyed)
		{
			std::cerr << "glaipnir: warning: cleanup of ephemeral session failed: " << core::describe(destroyed.error())
				<< "\n";
		}
	}
	return exit_code;
}

int glaipnir::cli::c_cli::command_policy()
{
	if (args_.size() != 3 || args_[1] != "check")
	{
		return detail::usage_error("usage: glaipnir policy check FILE");
	}
	auto policy = policy::c_policy::load_file(core::from_utf8(args_[2]), policy::host_context_t::detect(state_root_));
	if (!policy)
	{
		return detail::fail(policy.error());
	}
	std::cout << "# policy is valid; normalized form (digest " << policy->digest() << ")\n\n" << policy->to_toml();
	return 0;
}

int glaipnir::cli::c_cli::command_session()
{
	if (args_.size() < 2)
	{
		return detail::usage_error("usage: glaipnir session list|create|delete|fork|pause|resume|kill ...");
	}
	const auto& action = args_[1];
	if (action == "list" && args_.size() == 2)
	{
		auto ids = core::c_session::list(state_root_);
		if (!ids)
		{
			return detail::fail(ids.error());
		}
		for (const auto& id : *ids)
		{
			std::cout << id << "\n";
		}
		return 0;
	}
	if (action == "fork" && args_.size() == 4)
	{
		auto source = core::c_session::open({args_[2], state_root_, false}, open_mode::open_existing);
		if (!source)
		{
			return detail::fail(source.error());
		}
		auto child = source->fork_session(args_[3]);
		if (!child)
		{
			return detail::fail(child.error());
		}
		std::cout << "forked " << args_[2] << " -> " << args_[3] << "\n";
		return 0;
	}
	if (args_.size() != 3)
	{
		return detail::usage_error("usage: glaipnir session " + action + " ID");
	}
	const auto& id = args_[2];
	core::result_t<void> outcome = core::ok();
	if (action == "create")
	{
		auto session = core::c_session::open({id, state_root_, false}, open_mode::create);
		outcome = session ? core::ok() : core::result_t<void>{session.error()};
	}
	else if (action == "delete")
	{
		outcome = core::c_session::destroy(state_root_, id);
	}
	else if (action == "pause")
	{
		outcome = platform::pause_session(id, core::c_session::directory_for(state_root_, id));
	}
	else if (action == "resume")
	{
		outcome = platform::resume_session(id, core::c_session::directory_for(state_root_, id));
	}
	else if (action == "kill")
	{
		outcome = platform::terminate_session(id, core::c_session::directory_for(state_root_, id));
	}
	else
	{
		return detail::usage_error("unknown session action '" + action + "'");
	}
	if (!outcome)
	{
		return detail::fail(outcome.error());
	}
	std::cout << action << ": " << id << "\n";
	return 0;
}

int glaipnir::cli::c_cli::command_snapshot()
{
	if (args_.size() < 3)
	{
		return detail::usage_error("usage: glaipnir snapshot list|create|rollback|delete SESSION [LABEL]");
	}
	const auto& action = args_[1];
	auto session = core::c_session::open({args_[2], state_root_, false}, open_mode::open_existing);
	if (!session)
	{
		return detail::fail(session.error());
	}
	if (action == "list" && args_.size() == 3)
	{
		auto snapshots = session->snapshots();
		if (!snapshots)
		{
			return detail::fail(snapshots.error());
		}
		for (const auto& meta : *snapshots)
		{
			std::cout << std::format("{:<24} {}  {:>8} files  {:>12} bytes\n", meta.snapshot.label,
			                         meta.snapshot.created_at, meta.snapshot.files, meta.snapshot.bytes);
		}
		return 0;
	}
	if (args_.size() != 4)
	{
		return detail::usage_error("usage: glaipnir snapshot " + action + " SESSION LABEL");
	}
	const auto& label = args_[3];
	if (action == "create")
	{
		auto meta = session->snapshot(label);
		if (!meta)
		{
			return detail::fail(meta.error());
		}
		std::cout << std::format("snapshot {}: {} files, {} bytes\n", label, meta->snapshot.files,
		                         meta->snapshot.bytes);
		if (meta->snapshot.skipped_links != 0)
		{
			std::cerr << std::format("glaipnir: note: {} symlinks/junctions in the workspace were not captured\n",
			                         meta->snapshot.skipped_links);
		}
		return 0;
	}
	core::result_t<void> outcome = core::ok();
	if (action == "rollback")
	{
		outcome = session->rollback(label);
	}
	else if (action == "delete")
	{
		outcome = session->remove_snapshot(label);
	}
	else
	{
		return detail::usage_error("unknown snapshot action '" + action + "'");
	}
	if (!outcome)
	{
		return detail::fail(outcome.error());
	}
	std::cout << action << ": " << label << "\n";
	return 0;
}

int glaipnir::cli::c_cli::command_audit()
{
	if (args_.size() != 3 || args_[1] != "verify")
	{
		return detail::usage_error("usage: glaipnir audit verify SESSION");
	}
	auto count = core::c_audit_log::verify(core::c_session::audit_path_for(state_root_, args_[2]));
	if (!count)
	{
		return detail::fail(count.error());
	}
	std::cout << "audit log intact: " << *count << " records\n";
	return 0;
}
