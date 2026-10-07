#pragma once

#include <filesystem>

namespace glaipnir::core::detail
{
	bool component_equal(const std::filesystem::path& a, const std::filesystem::path& b);
}
