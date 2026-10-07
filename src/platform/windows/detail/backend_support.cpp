#include "platform/windows/detail/backend_support.hpp"

#include <algorithm>
#include <cctype>

#include "glaipnir/core/c_sha256.hpp"
#include "glaipnir/core/path_util.hpp"

std::string glaipnir::platform::windows::detail::session_key(std::string_view session_id,
                                                             const std::filesystem::path& session_dir)
{
	auto location = core::to_display_string(core::normalize_path(std::filesystem::absolute(session_dir)));
	std::transform(location.begin(), location.end(), location.begin(), [](unsigned char c)
	{
		return static_cast<char>(std::tolower(c));
	});
	return std::string{session_id} + "." + core::c_sha256::hex_digest(location).substr(0, 6);
}

std::string glaipnir::platform::windows::detail::container_moniker(std::string_view session_key)
{
	return "glaipnir." + std::string{session_key};
}

std::string_view glaipnir::platform::windows::detail::outcome_name(grant_outcome outcome)
{
	switch (outcome)
	{
	case grant_outcome::unchanged: return "unchanged";
	case grant_outcome::granted: return "granted";
	case grant_outcome::already_allowed: return "already_allowed";
	case grant_outcome::skipped: return "skipped";
	}
	return "unknown";
}
