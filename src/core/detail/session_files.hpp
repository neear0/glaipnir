#pragma once

#include <filesystem>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::core::detail
{
	inline constexpr std::string_view lock_file_name = ".lock";

	inline constexpr std::string_view session_meta_file_name = "session.toml";

	result_t<void> write_session_meta(const std::filesystem::path& directory);
}
