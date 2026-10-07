#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace glaipnir::policy
{
	enum class access_mode { read_only, read_write };

	enum class isolation_backend
	{
		automatic,
		app_container,
		restricted_token,
		windows_sandbox,
		process,
		firecracker,
	};

	enum class exposure_handling
	{
		refuse,
		warn,
		deny,
	};

	enum class network_mode
	{
		none,
		proxy,
		unrestricted,
	};

	struct path_rule_t
	{
		std::filesystem::path path;
		access_mode access = access_mode::read_only;
	};

	struct net_rule_t
	{
		std::string host_pattern;
		std::uint16_t port = 443;
	};

	struct resource_limit_t
	{
		std::uint64_t memory_bytes = 4ull * 1024 * 1024 * 1024;
		std::uint32_t max_processes = 128;
		std::uint32_t cpu_percent = 100;
		std::uint64_t wall_timeout_seconds = 0;
		std::uint64_t cpu_timeout_seconds = 0;
	};

	struct capability_t
	{
		bool child_processes = false;
		bool clipboard_read = false;
		bool clipboard_write = false;
		bool desktop_ui = false;
	};

	struct env_policy_t
	{
		std::vector<std::string> pass;
		std::vector<std::pair<std::string, std::string>> set;
	};

	struct policy_t
	{
		std::string name = "unnamed";
		isolation_backend backend = isolation_backend::automatic;
		bool less_privileged = false;
		exposure_handling exposed_folders = exposure_handling::refuse;
		std::vector<path_rule_t> paths;
		network_mode network = network_mode::none;
		std::vector<net_rule_t> net_rules;
		env_policy_t env;
		resource_limit_t limits;
		capability_t capabilities;
	};
}
