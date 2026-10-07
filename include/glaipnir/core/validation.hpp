#pragma once

#include <cstddef>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::core {

/// Longest accepted session id / snapshot label. Windows caps AppContainer monikers at 64
/// characters and we prepend "glaipnir.", so ids must stay well under that.
inline constexpr std::size_t max_identifier_length = 48;

/// Checks a session id or snapshot label.
///
/// These strings become directory names and AppContainer monikers, so they are limited to
/// `[a-z0-9_-]`, must start with a letter or digit, and must not be a reserved Windows device
/// name. Lowercase-only avoids two ids colliding on case-insensitive filesystems.
/// @param value candidate identifier
/// @param what  noun used in the error message ("session id", "snapshot label")
result_t<void> validate_identifier(std::string_view value, std::string_view what);

} // namespace glaipnir::core
