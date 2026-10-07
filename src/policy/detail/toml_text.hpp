#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"
#include "policy/detail/policy_checks.hpp"

namespace glaipnir::policy::detail {

std::string quote_toml_string(std::string_view text);

template <typename enum_type, std::size_t count>
core::result_t<enum_type> parse_enum(std::string_view text, const std::array<enum_type, count>& values, std::string_view what) {
    std::string allowed;
    for (const auto value : values) {
        if (to_string(value) == text) {
            return value;
        }
        allowed += allowed.empty() ? "" : ", ";
        allowed += to_string(value);
    }
    return policy_error(std::string{what} + " '" + std::string{text} + "' is unknown (expected one of: " + allowed + ")");
}

}
