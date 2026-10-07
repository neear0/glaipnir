#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "glaipnir/platform/windows/path_acl.hpp"
#include "platform/windows/detail/win_util.hpp"

namespace glaipnir::platform::windows::detail
{
	inline constexpr unsigned timeout_exit_code = 124;
	inline constexpr unsigned terminated_exit_code = 137;

	struct well_known_sid_t
	{
		std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> bytes{};
	};

	std::string session_key(std::string_view session_id, const std::filesystem::path& session_dir);

	std::string container_moniker(std::string_view session_key);

	std::string_view outcome_name(grant_outcome outcome);
}
