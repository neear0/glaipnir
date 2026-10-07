#include "platform/windows/detail/exposure_scan.hpp"

#include <system_error>

#include "glaipnir/platform/windows/path_acl.hpp"
#include "platform/windows/detail/win_util.hpp"

std::vector<std::filesystem::path> glaipnir::platform::windows::detail::find_exposed_directories(
	const std::filesystem::path& root, int max_depth, std::span<void* const> groups)
{
	std::vector<std::filesystem::path> exposed;
	std::vector<std::pair<std::filesystem::path, int>> pending{{root, 0}};
	while (!pending.empty())
	{
		auto [directory, depth] = std::move(pending.back());
		pending.pop_back();
		const DWORD attributes = GetFileAttributesW(directory.c_str());
		if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
			(attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
		{
			continue;
		}
		if (auto result = is_exposed_to(directory, groups); result && *result)
		{
			exposed.push_back(directory);
		}
		if (depth >= max_depth)
		{
			continue;
		}
		std::error_code ec;
		for (std::filesystem::directory_iterator it{directory, ec}, end; !ec && it != end; it.increment(ec))
		{
			pending.emplace_back(it->path(), depth + 1);
		}
	}
	return exposed;
}
