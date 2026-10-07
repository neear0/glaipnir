#include "policy/detail/toml_text.hpp"

#include <format>

std::string glaipnir::policy::detail::quote_toml_string(std::string_view text)
{
	std::string out = "\"";
	for (const char c : text)
	{
		switch (c)
		{
		case '"': out += "\\\"";
			break;
		case '\\': out += "\\\\";
			break;
		case '\n': out += "\\n";
			break;
		case '\r': out += "\\r";
			break;
		case '\t': out += "\\t";
			break;
		case '\b': out += "\\b";
			break;
		case '\f': out += "\\f";
			break;
		default:
			if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f)
			{
				out += std::format("\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(c)));
			}
			else
			{
				out += c;
			}
		}
	}
	out += '"';
	return out;
}
