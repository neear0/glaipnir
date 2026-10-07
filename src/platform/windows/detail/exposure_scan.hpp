#pragma once

#include <filesystem>
#include <span>
#include <vector>

namespace glaipnir::platform::windows::detail
{
	inline constexpr int exposure_scan_depth = 3;

	std::vector<std::filesystem::path> find_exposed_directories(const std::filesystem::path& root, int max_depth,
	                                                            std::span<void* const> groups);
}
