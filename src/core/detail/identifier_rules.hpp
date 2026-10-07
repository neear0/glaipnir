#pragma once

#include <string_view>

namespace glaipnir::core::detail {

bool is_lower_alnum(char c) noexcept;

bool is_reserved_device_name(std::string_view value) noexcept;

}
