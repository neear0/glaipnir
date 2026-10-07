#pragma once

#include <cstddef>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::core {

inline constexpr std::size_t max_identifier_length = 48;

result_t<void> validate_identifier(std::string_view value, std::string_view what);

}
