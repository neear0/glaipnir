#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glaipnir::isolation
{
	enum class termination_reason
	{
		exited,
		wall_timeout,
		cpu_timeout,
		terminated,
	};

	struct sandbox_result_t
	{
		int exit_code = -1;
		termination_reason reason = termination_reason::exited;
		std::chrono::milliseconds wall_time{0};
		std::chrono::milliseconds cpu_time{0};
		std::uint64_t peak_memory_bytes = 0;
	};

	struct launch_spec_t
	{
		std::vector<std::string> argv;
		std::filesystem::path working_directory;
		std::vector<std::pair<std::string, std::string>> environment;
	};

	std::string_view to_string(termination_reason reason) noexcept;
}
