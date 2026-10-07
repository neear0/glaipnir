#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "glaipnir/core/error.hpp"

namespace glaipnir::policy::detail
{
	class c_toml_parser;
}

namespace glaipnir::policy
{
	struct toml_value_t
	{
		std::variant<std::string, std::int64_t, bool, std::vector<std::string>> data;
		std::size_t line = 0;
	};

	class c_toml_reader
	{
	public:
		static core::result_t<c_toml_reader> parse(std::string_view text);

		const std::map<std::string, toml_value_t>& entries() const noexcept { return entries_; }

		const std::vector<std::string>& tables() const noexcept { return tables_; }

	private:
		std::map<std::string, toml_value_t> entries_;
		std::vector<std::string> tables_;

		friend class detail::c_toml_parser;
	};
}
