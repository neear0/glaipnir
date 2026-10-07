#include "glaipnir/core/c_sandbox.hpp"

#include <format>

#include "glaipnir/core/path_util.hpp"

glaipnir::core::c_sandbox::c_sandbox(policy::c_policy policy, c_session& session, platform::platform_backend backend)
	: policy_(std::move(policy)), session_(&session), backend_(std::move(backend))
{
}

glaipnir::core::result_t<glaipnir::core::c_sandbox> glaipnir::core::c_sandbox::create(policy::c_policy policy,
	c_session& session)
{
	(void)session.audit().record("policy.apply", std::format("name={} digest={}", policy.data().name, policy.digest()));
	auto backend = platform::platform_backend::prepare(policy, session.session_id(), session.directory(),
	                                                   session.volume().workspace(), session.audit());
	if (!backend)
	{
		(void)session.audit().record("policy.reject", describe(backend.error()));
		return std::move(backend).error();
	}
	return c_sandbox{std::move(policy), session, std::move(*backend)};
}

glaipnir::core::result_t<void> glaipnir::core::c_sandbox::start(const std::vector<std::string>& argv,
                                                                const std::filesystem::path& working_directory)
{
	const auto workspace = session_->volume().workspace();
	std::filesystem::path cwd = workspace;
	if (!working_directory.empty())
	{
		cwd = normalize_path(working_directory.is_absolute() ? working_directory : workspace / working_directory);
		if (!is_same_or_inside(cwd, workspace))
		{
			return make_error(error_code::invalid_argument, "working directory must be inside the session workspace");
		}
	}

	isolation::launch_spec_t spec;
	spec.argv = argv;
	spec.working_directory = cwd;
	for (const auto& name : policy_.data().env.pass)
	{
		if (auto value = host_env(name.c_str()); !value.empty())
		{
			spec.environment.emplace_back(name, std::move(value));
		}
	}
	for (const auto& item : policy_.data().env.set)
	{
		spec.environment.push_back(item);
	}

	std::string command;
	for (const auto& arg : argv)
	{
		command += command.empty() ? "" : " ";
		command += arg;
	}
	auto started = backend_.start(spec);
	if (!started)
	{
		(void)session_->audit().record("exec.fail", command + " :: " + describe(started.error()));
		return started;
	}
	(void)session_->audit().record("exec.start", command);
	return ok();
}

glaipnir::core::result_t<glaipnir::isolation::sandbox_result_t> glaipnir::core::c_sandbox::wait()
{
	auto result = backend_.wait();
	if (result)
	{
		(void)session_->audit().record(
			"exec.end", std::format("exit={} reason={} wall_ms={} cpu_ms={} peak_mem={}", result->exit_code,
			                        isolation::to_string(result->reason), result->wall_time.count(),
			                        result->cpu_time.count(), result->peak_memory_bytes));
	}
	return result;
}

glaipnir::core::result_t<glaipnir::isolation::sandbox_result_t>
glaipnir::core::c_sandbox::run(const std::vector<std::string>& argv, const std::filesystem::path& working_directory)
{
	auto started = start(argv, working_directory);
	if (!started)
	{
		return std::move(started).error();
	}
	return wait();
}

glaipnir::core::result_t<void> glaipnir::core::c_sandbox::pause()
{
	auto paused = backend_.pause();
	if (paused)
	{
		(void)session_->audit().record("exec.pause", "");
	}
	return paused;
}

glaipnir::core::result_t<void> glaipnir::core::c_sandbox::resume()
{
	auto resumed = backend_.resume();
	if (resumed)
	{
		(void)session_->audit().record("exec.resume", "");
	}
	return resumed;
}

glaipnir::core::result_t<void> glaipnir::core::c_sandbox::terminate() const
{
	return backend_.terminate();
}
