#include "core/detail/path_compare.hpp"

#include <cwctype>

bool glaipnir::core::detail::component_equal(const std::filesystem::path& a, const std::filesystem::path& b)
{
#ifdef _WIN32
	const auto& left = a.native();
	const auto& right = b.native();
	if (left.size() != right.size())
	{
		return false;
	}
	for (std::size_t i = 0; i < left.size(); ++i)
	{
		if (std::towlower(left[i]) != std::towlower(right[i]))
		{
			return false;
		}
	}
	return true;
#else
	return a == b;
#endif
}
