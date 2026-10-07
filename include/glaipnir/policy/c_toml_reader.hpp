#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "glaipnir/core/error.hpp"

namespace glaipnir::policy {

/// One parsed value plus the line it came from, for error messages.
struct toml_value_t {
    std::variant<std::string, std::int64_t, bool, std::vector<std::string>> data;
    std::size_t line = 0;
};

/// Strict reader for the TOML subset used by policy files.
///
/// Supported: `[table]` and `[table.sub]` headers, `key = value`, basic and literal strings,
/// integers, booleans and arrays of strings (multi-line, trailing comma), `#` comments.
/// Everything else (inline tables, dates, floats, multi-line strings, dotted keys) is rejected
/// rather than guessed at, so a policy never means something other than what it says.
class c_toml_reader {
public:
    /// Parses `text`. Duplicate keys and duplicate tables are errors.
    static core::result_t<c_toml_reader> parse(std::string_view text);

    /// All values keyed by "table.key" (or just "key" before the first header).
    const std::map<std::string, toml_value_t>& entries() const noexcept { return entries_; }

    /// Every table header that appeared, including empty tables.
    const std::vector<std::string>& tables() const noexcept { return tables_; }

private:
    std::map<std::string, toml_value_t> entries_;
    std::vector<std::string> tables_;

    friend class c_toml_parser;
};

} // namespace glaipnir::policy
