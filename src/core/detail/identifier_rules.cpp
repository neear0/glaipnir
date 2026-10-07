#include "core/detail/identifier_rules.hpp"

#include <array>

bool glaipnir::core::detail::is_lower_alnum(char c) noexcept
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

bool glaipnir::core::detail::is_reserved_device_name(std::string_view value) noexcept
{
	constexpr std::array<std::string_view, 4> fixed{"con", "prn", "aux", "nul"};
	for (const auto name : fixed)
	{
		if (value == name)
		{
			return true;
		}
	}
	if (value.size() == 4 && (value.starts_with("com") || value.starts_with("lpt")))
	{
		return value[3] >= '0' && value[3] <= '9';
	}
	return false;
}
