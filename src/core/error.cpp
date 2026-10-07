#include "glaipnir/core/error.hpp"

namespace glaipnir::core {

std::string_view to_string(error_code code) noexcept {
    switch (code) {
    case error_code::invalid_argument: return "invalid_argument";
    case error_code::invalid_policy: return "invalid_policy";
    case error_code::parse_error: return "parse_error";
    case error_code::not_found: return "not_found";
    case error_code::already_exists: return "already_exists";
    case error_code::io_error: return "io_error";
    case error_code::permission_denied: return "permission_denied";
    case error_code::platform_error: return "platform_error";
    case error_code::not_supported: return "not_supported";
    case error_code::busy: return "busy";
    case error_code::integrity_error: return "integrity_error";
    }
    return "unknown";
}

std::string describe(const error_t& error) {
    std::string text{to_string(error.code)};
    text += ": ";
    text += error.message;
    if (error.native_code != 0) {
        text += " (native ";
        text += std::to_string(error.native_code);
        text += ")";
    }
    return text;
}

} // namespace glaipnir::core
