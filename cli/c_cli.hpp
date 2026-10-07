#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace glaipnir::cli
{
	inline constexpr int exit_usage = 2;
	inline constexpr int exit_timeout = 124;
	inline constexpr int exit_internal = 125;

	class c_cli
	{
	public:
		explicit c_cli(std::vector<std::string> args);

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
}
