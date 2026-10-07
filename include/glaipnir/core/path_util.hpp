#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace glaipnir::core {

/// True when `child` equals `parent` or lies beneath it, comparing whole components.
///
/// Comparison is case-insensitive on Windows because NTFS lookups are; a case-sensitive check
/// there would let "C:/USERS/me" slip past a rule written for "C:/Users/me".
/// Both paths should already be absolute and normalized.
bool is_same_or_inside(const std::filesystem::path& child, const std::filesystem::path& parent);

/// Lexically normalizes `path` and removes a trailing separator, so equal paths compare equal.
std::filesystem::path normalize_path(const std::filesystem::path& path);

/// UTF-8 rendering of a path with forward slashes, for logs, TOML output and messages.
std::string to_display_string(const std::filesystem::path& path);

/// Builds a path from UTF-8 text. Plain `path(std::string)` uses the ANSI code page on Windows,
/// which would mangle non-ASCII policy paths.
std::filesystem::path from_utf8(std::string_view text);

/// Reads an environment variable of the host process; empty when unset.
std::string host_env(const char* name);

} // namespace glaipnir::core
