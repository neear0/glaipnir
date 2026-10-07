#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows {

std::wstring quote_argument(std::wstring_view argument);

core::result_t<std::wstring> build_command_line(const std::vector<std::wstring>& argv);

core::result_t<std::filesystem::path> resolve_executable(std::wstring_view name, std::wstring_view search_path,
                                                         std::wstring_view extensions);

}
