#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace glaipnir::core
{
	bool is_same_or_inside(const std::filesystem::path& child, const std::filesystem::path& parent);

	std::filesystem::path normalize_path(const std::filesystem::path& path);

	std::string to_display_string(const std::filesystem::path& path);

	std::filesystem::path from_utf8(std::string_view text);

	std::string host_env(const char* name);
}
