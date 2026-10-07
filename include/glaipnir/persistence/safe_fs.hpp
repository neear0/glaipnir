#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

#include "glaipnir/core/error.hpp"

namespace glaipnir::persistence
{
	struct tree_stats_t
	{
		std::uint64_t files = 0;
		std::uint64_t directories = 0;
		std::uint64_t bytes = 0;
		std::vector<std::filesystem::path> skipped;
	};

	core::result_t<tree_stats_t> copy_tree(const std::filesystem::path& source,
	                                       const std::filesystem::path& destination);

	core::result_t<void> remove_tree(const std::filesystem::path& root);

	core::result_t<tree_stats_t> measure_tree(const std::filesystem::path& root);
}
