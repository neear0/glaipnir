#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace glaipnir::platform::windows::detail
{
	std::vector<std::wstring> split_list(std::wstring_view text, wchar_t separator);

	bool is_existing_file(const std::filesystem::path& path);
}
