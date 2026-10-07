#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/c_toml_reader.hpp"

namespace glaipnir::policy::detail
{
	class c_toml_parser
	{
	public:
		explicit c_toml_parser(std::string_view text) : text_(text)
		{
		}

		core::result_t<c_toml_reader> run();

	private:
		using value_variant = decltype(toml_value_t::data);

		bool at_end() const noexcept { return pos_ >= text_.size(); }
		char peek() const noexcept { return at_end() ? '\0' : text_[pos_]; }
		bool consume(char expected) noexcept;

		core::error_t fail(std::string message) const;
		static core::error_t fail_at(std::size_t line, std::string message);

		void skip_inline_space() noexcept;
		void skip_comment() noexcept;
		bool consume_newline() noexcept;
		void skip_blank_lines() noexcept;
		core::result_t<void> expect_line_end();

		static bool is_bare_key_char(char c) noexcept;
		static void append_utf8(std::string& out, std::uint32_t code_point);

		core::result_t<std::string> parse_key();
		core::result_t<std::string> parse_table_header();
		core::result_t<value_variant> parse_value();
		core::result_t<std::int64_t> parse_integer();
		core::result_t<std::vector<std::string>> parse_string_array();
		core::result_t<std::string> parse_literal_string();
		core::result_t<std::uint32_t> parse_unicode_escape(std::size_t digit_count);
		core::result_t<std::string> parse_basic_string();

		std::string_view text_;
		std::size_t pos_ = 0;
		std::size_t line_ = 1;
	};
}
