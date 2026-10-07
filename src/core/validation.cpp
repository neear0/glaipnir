#include "glaipnir/core/validation.hpp"

#include <string>

#include "core/detail/identifier_rules.hpp"

glaipnir::core::result_t<void> glaipnir::core::validate_identifier(std::string_view value, std::string_view what)
{
	const std::string noun{what};
	if (value.empty())
	{
		return make_error(error_code::invalid_argument, noun + " must not be empty");
	}
	if (value.size() > max_identifier_length)
	{
		return make_error(error_code::invalid_argument,
		                  noun + " is longer than " + std::to_string(max_identifier_length) + " characters");
	}
	if (!detail::is_lower_alnum(value.front()))
	{
		return make_error(error_code::invalid_argument, noun + " must start with a lowercase letter or digit");
	}
	for (const char c : value)
	{
		if (!detail::is_lower_alnum(c) && c != '-' && c != '_')
		{
			return make_error(error_code::invalid_argument,
			                  noun + " may only contain lowercase letters, digits, '-' and '_'");
		}
	}
	if (detail::is_reserved_device_name(value))
	{
		return make_error(error_code::invalid_argument,
		                  noun + " '" + std::string{value} + "' is a reserved device name");
	}
	return ok();
}
