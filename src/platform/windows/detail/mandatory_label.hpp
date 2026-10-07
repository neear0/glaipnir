#pragma once

#include <filesystem>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows::detail
{
	core::result_t<bool> apply_low_label(const std::filesystem::path& path);

	core::result_t<void> remove_label(const std::filesystem::path& path);
}
