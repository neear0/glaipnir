#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows {

/// Quotes one argument so that CommandLineToArgvW and the MSVC CRT parse it back verbatim.
///
/// Windows passes a single command-line string, not an argv array; naive quoting lets an
/// argument containing `"` or trailing backslashes split into several or swallow the next one.
std::wstring quote_argument(std::wstring_view argument);

/// Joins arguments into one command line using quote_argument().
/// argv[0] must not contain '"' (the program name is parsed without escape processing).
core::result_t<std::wstring> build_command_line(const std::vector<std::wstring>& argv);

/// Finds `name` the way a shell would: absolute/relative paths are taken as-is, bare names are
/// searched in `search_path` (a PATH value) trying each `extensions` entry (a PATHEXT value).
/// Unlike SearchPathW, never looks in glaipnir's own directory or the current directory first.
core::result_t<std::filesystem::path> resolve_executable(std::wstring_view name, std::wstring_view search_path,
                                                         std::wstring_view extensions);

} // namespace glaipnir::platform::windows
