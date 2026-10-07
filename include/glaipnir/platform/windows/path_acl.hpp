#pragma once

#include <filesystem>
#include <span>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows
{
	enum class grant_outcome
	{
		unchanged,
		granted,
		already_allowed,
		skipped,
	};

	enum class grant_kind
	{
		read_only,
		read_write,
		traverse,
		deny,
	};

	core::result_t<grant_outcome> grant_path_access(const std::filesystem::path& path, void* sid, grant_kind kind,
	                                                std::span<void* const> baseline_groups);

	core::result_t<void> revoke_path_access(const std::filesystem::path& path, void* sid);

	core::result_t<bool> is_exposed_to(const std::filesystem::path& path, std::span<void* const> groups);
}
