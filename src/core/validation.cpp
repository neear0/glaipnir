#include "glaipnir/core/validation.hpp"

#include <array>
#include <string>

namespace glaipnir::core {

namespace {

bool is_lower_alnum(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

// Windows resolves these names to devices in every directory, so "nul" as a session id would
// silently discard writes instead of creating a folder.
bool is_reserved_device_name(std::string_view value) noexcept {
    constexpr std::array<std::string_view, 4> fixed{"con", "prn", "aux", "nul"};
    for (const auto name : fixed) {
        if (value == name) {
            return true;
        }
    }
    if (value.size() == 4 && (value.starts_with("com") || value.starts_with("lpt"))) {
        return value[3] >= '0' && value[3] <= '9';
    }
    return false;
}

} // namespace

result_t<void> validate_identifier(std::string_view value, std::string_view what) {
    const std::string noun{what};
    if (value.empty()) {
        return make_error(error_code::invalid_argument, noun + " must not be empty");
    }
    if (value.size() > max_identifier_length) {
        return make_error(error_code::invalid_argument,
                          noun + " is longer than " + std::to_string(max_identifier_length) + " characters");
    }
    if (!is_lower_alnum(value.front())) {
        return make_error(error_code::invalid_argument, noun + " must start with a lowercase letter or digit");
    }
    for (const char c : value) {
        if (!is_lower_alnum(c) && c != '-' && c != '_') {
            return make_error(error_code::invalid_argument,
                              noun + " may only contain lowercase letters, digits, '-' and '_'");
        }
    }
    if (is_reserved_device_name(value)) {
        return make_error(error_code::invalid_argument, noun + " '" + std::string{value} + "' is a reserved device name");
    }
    return ok();
}

} // namespace glaipnir::core
