#include "policy/detail/c_toml_parser.hpp"

#include <limits>
#include <set>

using glaipnir::core::error_code;
using glaipnir::core::make_error;
using glaipnir::core::result_t;

result_t<glaipnir::policy::c_toml_reader> glaipnir::policy::detail::c_toml_parser::run() {
    c_toml_reader reader;
    std::string current_table;
    std::set<std::string> seen_tables;

    while (true) {
        skip_blank_lines();
        if (at_end()) {
            break;
        }
        if (peek() == '[') {
            auto header = parse_table_header();
            if (!header) {
                return std::move(header).error();
            }
            if (!seen_tables.insert(*header).second) {
                return fail("table [" + *header + "] defined twice");
            }
            current_table = *header;
            reader.tables_.push_back(current_table);
        } else {
            const std::size_t key_line = line_;
            auto key = parse_key();
            if (!key) {
                return std::move(key).error();
            }
            skip_inline_space();
            if (peek() == '.') {
                return fail("dotted keys are not supported; use a [table] header instead");
            }
            if (!consume('=')) {
                return fail("expected '=' after key '" + *key + "'");
            }
            skip_inline_space();
            auto value = parse_value();
            if (!value) {
                return std::move(value).error();
            }
            const std::string full_key = current_table.empty() ? *key : current_table + "." + *key;
            toml_value_t entry{std::move(*value), key_line};
            if (!reader.entries_.emplace(full_key, std::move(entry)).second) {
                return fail_at(key_line, "key '" + full_key + "' defined twice");
            }
        }
        auto end = expect_line_end();
        if (!end) {
            return std::move(end).error();
        }
    }
    return reader;
}

bool glaipnir::policy::detail::c_toml_parser::consume(char expected) noexcept {
    if (peek() != expected) {
        return false;
    }
    ++pos_;
    return true;
}

glaipnir::core::error_t glaipnir::policy::detail::c_toml_parser::fail(std::string message) const {
    return fail_at(line_, std::move(message));
}

glaipnir::core::error_t glaipnir::policy::detail::c_toml_parser::fail_at(std::size_t line, std::string message) {
    return make_error(error_code::parse_error, "line " + std::to_string(line) + ": " + message);
}

void glaipnir::policy::detail::c_toml_parser::skip_inline_space() noexcept {
    while (peek() == ' ' || peek() == '\t') {
        ++pos_;
    }
}

void glaipnir::policy::detail::c_toml_parser::skip_comment() noexcept {
    if (peek() == '#') {
        while (!at_end() && peek() != '\n') {
            ++pos_;
        }
    }
}

bool glaipnir::policy::detail::c_toml_parser::consume_newline() noexcept {
    if (peek() == '\r' && pos_ + 1 < text_.size() && text_[pos_ + 1] == '\n') {
        pos_ += 2;
        ++line_;
        return true;
    }
    if (peek() == '\n') {
        ++pos_;
        ++line_;
        return true;
    }
    return false;
}

void glaipnir::policy::detail::c_toml_parser::skip_blank_lines() noexcept {
    while (true) {
        skip_inline_space();
        skip_comment();
        if (!consume_newline()) {
            return;
        }
    }
}

result_t<void> glaipnir::policy::detail::c_toml_parser::expect_line_end() {
    skip_inline_space();
    skip_comment();
    if (at_end() || consume_newline()) {
        return glaipnir::core::ok();
    }
    return fail(std::string{"unexpected '"} + peek() + "' after value");
}

bool glaipnir::policy::detail::c_toml_parser::is_bare_key_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}

result_t<std::string> glaipnir::policy::detail::c_toml_parser::parse_key() {
    if (peek() == '"') {
        return parse_basic_string();
    }
    if (peek() == '\'') {
        return parse_literal_string();
    }
    const std::size_t start = pos_;
    while (is_bare_key_char(peek())) {
        ++pos_;
    }
    if (pos_ == start) {
        return fail("expected a key");
    }
    return std::string{text_.substr(start, pos_ - start)};
}

result_t<std::string> glaipnir::policy::detail::c_toml_parser::parse_table_header() {
    consume('[');
    if (peek() == '[') {
        return fail("arrays of tables ([[...]]) are not supported");
    }
    std::string name;
    while (true) {
        skip_inline_space();
        auto part = parse_key();
        if (!part) {
            return part;
        }
        name += *part;
        skip_inline_space();
        if (consume(']')) {
            return name;
        }
        if (!consume('.')) {
            return fail("expected '.' or ']' in table header");
        }
        name += '.';
    }
}

result_t<glaipnir::policy::detail::c_toml_parser::value_variant> glaipnir::policy::detail::c_toml_parser::parse_value() {
    const char c = peek();
    if (c == '"') {
        if (text_.substr(pos_).starts_with("\"\"\"")) {
            return fail("multi-line strings are not supported");
        }
        auto text = parse_basic_string();
        if (!text) {
            return std::move(text).error();
        }
        return value_variant{std::move(*text)};
    }
    if (c == '\'') {
        if (text_.substr(pos_).starts_with("'''")) {
            return fail("multi-line strings are not supported");
        }
        auto text = parse_literal_string();
        if (!text) {
            return std::move(text).error();
        }
        return value_variant{std::move(*text)};
    }
    if (c == '[') {
        auto list = parse_string_array();
        if (!list) {
            return std::move(list).error();
        }
        return value_variant{std::move(*list)};
    }
    if (c == '{') {
        return fail("inline tables are not supported; use a [table] header instead");
    }
    if (text_.substr(pos_).starts_with("true")) {
        pos_ += 4;
        return value_variant{true};
    }
    if (text_.substr(pos_).starts_with("false")) {
        pos_ += 5;
        return value_variant{false};
    }
    if (c == '+' || c == '-' || (c >= '0' && c <= '9')) {
        auto number = parse_integer();
        if (!number) {
            return std::move(number).error();
        }
        return value_variant{*number};
    }
    return fail("expected a string, integer, boolean or array");
}

result_t<std::int64_t> glaipnir::policy::detail::c_toml_parser::parse_integer() {
    bool negative = false;
    if (peek() == '+' || peek() == '-') {
        negative = peek() == '-';
        ++pos_;
    }
    const std::size_t digits_start = pos_;
    std::uint64_t magnitude = 0;
    bool previous_was_digit = false;
    constexpr std::uint64_t limit = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    while (true) {
        const char c = peek();
        if (c >= '0' && c <= '9') {
            const auto digit = static_cast<std::uint64_t>(c - '0');
            if (magnitude > (limit - digit) / 10) {
                return fail("integer out of range");
            }
            magnitude = magnitude * 10 + digit;
            previous_was_digit = true;
            ++pos_;
        } else if (c == '_' && previous_was_digit) {
            previous_was_digit = false;
            ++pos_;
        } else {
            break;
        }
    }
    const auto digits = text_.substr(digits_start, pos_ - digits_start);
    if (digits.empty() || !previous_was_digit) {
        return fail("malformed integer");
    }
    if (digits.size() > 1 && digits.front() == '0') {
        return fail("leading zeros (and hex/octal prefixes) are not allowed in integers");
    }
    if (peek() == '.' || peek() == 'e' || peek() == 'E' || peek() == 'x' || peek() == 'o' || peek() == 'b') {
        return fail("only decimal integers are supported");
    }
    const auto value = static_cast<std::int64_t>(magnitude);
    return negative ? -value : value;
}

result_t<std::vector<std::string>> glaipnir::policy::detail::c_toml_parser::parse_string_array() {
    consume('[');
    std::vector<std::string> items;
    while (true) {
        skip_blank_lines();
        if (consume(']')) {
            return items;
        }
        if (peek() != '"' && peek() != '\'') {
            return fail("arrays may only contain strings");
        }
        auto item = peek() == '"' ? parse_basic_string() : parse_literal_string();
        if (!item) {
            return item.error();
        }
        items.push_back(std::move(*item));
        skip_blank_lines();
        if (consume(']')) {
            return items;
        }
        if (!consume(',')) {
            return fail("expected ',' or ']' in array");
        }
    }
}

result_t<std::string> glaipnir::policy::detail::c_toml_parser::parse_literal_string() {
    consume('\'');
    std::string value;
    while (true) {
        if (at_end() || peek() == '\n' || peek() == '\r') {
            return fail("unterminated string");
        }
        const char c = text_[pos_++];
        if (c == '\'') {
            return value;
        }
        if (static_cast<unsigned char>(c) < 0x20 && c != '\t') {
            return fail("control characters are not allowed in strings");
        }
        value += c;
    }
}

void glaipnir::policy::detail::c_toml_parser::append_utf8(std::string& out, std::uint32_t code_point) {
    if (code_point < 0x80) {
        out += static_cast<char>(code_point);
    } else if (code_point < 0x800) {
        out += static_cast<char>(0xc0 | (code_point >> 6));
        out += static_cast<char>(0x80 | (code_point & 0x3f));
    } else if (code_point < 0x10000) {
        out += static_cast<char>(0xe0 | (code_point >> 12));
        out += static_cast<char>(0x80 | ((code_point >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (code_point & 0x3f));
    } else {
        out += static_cast<char>(0xf0 | (code_point >> 18));
        out += static_cast<char>(0x80 | ((code_point >> 12) & 0x3f));
        out += static_cast<char>(0x80 | ((code_point >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (code_point & 0x3f));
    }
}

result_t<std::uint32_t> glaipnir::policy::detail::c_toml_parser::parse_unicode_escape(std::size_t digit_count) {
    std::uint32_t code_point = 0;
    for (std::size_t i = 0; i < digit_count; ++i) {
        const char c = peek();
        std::uint32_t digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<std::uint32_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<std::uint32_t>(c - 'A' + 10);
        } else {
            return fail("malformed unicode escape");
        }
        code_point = code_point * 16 + digit;
        ++pos_;
    }
    if (code_point > 0x10ffff || (code_point >= 0xd800 && code_point <= 0xdfff)) {
        return fail("unicode escape is not a valid scalar value");
    }
    return code_point;
}

result_t<std::string> glaipnir::policy::detail::c_toml_parser::parse_basic_string() {
    consume('"');
    std::string value;
    while (true) {
        if (at_end() || peek() == '\n' || peek() == '\r') {
            return fail("unterminated string");
        }
        const char c = text_[pos_++];
        if (c == '"') {
            return value;
        }
        if (c != '\\') {
            if (static_cast<unsigned char>(c) < 0x20 && c != '\t') {
                return fail("control characters are not allowed in strings");
            }
            value += c;
            continue;
        }
        const char escape = peek();
        ++pos_;
        switch (escape) {
        case 'b': value += '\b'; break;
        case 't': value += '\t'; break;
        case 'n': value += '\n'; break;
        case 'f': value += '\f'; break;
        case 'r': value += '\r'; break;
        case '"': value += '"'; break;
        case '\\': value += '\\'; break;
        case 'u':
        case 'U': {
            auto code_point = parse_unicode_escape(escape == 'u' ? 4 : 8);
            if (!code_point) {
                return std::move(code_point).error();
            }
            append_utf8(value, *code_point);
            break;
        }
        default:
            return fail(std::string{"invalid escape '\\"} + escape +
                        "' (for Windows paths use forward slashes or 'literal strings')");
        }
    }
}
