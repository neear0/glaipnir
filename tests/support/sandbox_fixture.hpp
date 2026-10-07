#pragma once

#ifdef _WIN32

#include <filesystem>
#include <string>
#include <string_view>

#include "glaipnir/core/c_session.hpp"
#include "glaipnir/isolation/isolation_types.hpp"
#include "glaipnir/policy/c_policy.hpp"
#include "support/test_harness.hpp"

namespace glaipnir::test
{
	inline constexpr std::string_view cmd_exe = "C:\\Windows\\System32\\cmd.exe";

	struct sandbox_fixture_t
	{
		c_temp_dir temp;
		policy::host_context_t host;

		sandbox_fixture_t();
		~sandbox_fixture_t();
		sandbox_fixture_t(const sandbox_fixture_t&) = delete;
		sandbox_fixture_t& operator=(const sandbox_fixture_t&) = delete;

		std::filesystem::path state_root() const;
		core::result_t<policy::c_policy> policy_from(const std::string& text) const;
		core::result_t<core::c_session> session(const std::string& id) const;
		std::filesystem::path workspace(const std::string& id) const;

		core::result_t<isolation::sandbox_result_t> run(const std::string& id, const std::string& policy_text,
		                                                const std::string& line) const;
	};

	std::string path_text(const std::filesystem::path& path);
}

#endif
