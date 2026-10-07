#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace glaipnir::platform::windows::detail
{
	std::string exposure_refusal(const std::vector<std::filesystem::path>& exposed);

	std::string exposure_warning(const std::vector<std::filesystem::path>& exposed);

	std::string exposure_denial(const std::vector<std::filesystem::path>& exposed);

	std::string restricted_token_limits();
}
