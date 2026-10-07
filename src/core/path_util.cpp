#include "glaipnir/core/path_util.hpp"

#include <cstdlib>
#include <cwctype>

#ifdef _WIN32
#include <vector>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace glaipnir::core {

namespace {

bool component_equal(const std::filesystem::path& a, const std::filesystem::path& b) {
#ifdef _WIN32
    const auto& left = a.native();
    const auto& right = b.native();
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t i = 0; i < left.size(); ++i) {
        if (std::towlower(left[i]) != std::towlower(right[i])) {
            return false;
        }
    }
    return true;
#else
    return a == b;
#endif
}

} // namespace

std::filesystem::path normalize_path(const std::filesystem::path& path) {
    auto normal = path.lexically_normal();
    // "C:/a/b/" normalizes with an empty final element; drop it so it equals "C:/a/b".
    if (!normal.has_filename() && normal.has_relative_path()) {
        normal = normal.parent_path();
    }
    return normal;
}

bool is_same_or_inside(const std::filesystem::path& child, const std::filesystem::path& parent) {
    const auto child_normal = normalize_path(child);
    const auto parent_normal = normalize_path(parent);
    auto child_it = child_normal.begin();
    for (auto parent_it = parent_normal.begin(); parent_it != parent_normal.end(); ++parent_it, ++child_it) {
        if (child_it == child_normal.end()) {
            return false;
        }
        // Root directory components ("/" vs "\") differ textually but mean the same thing.
        if (parent_it->has_root_directory() && child_it->has_root_directory() && parent_it->native().size() == 1) {
            continue;
        }
        if (!component_equal(*child_it, *parent_it)) {
            return false;
        }
    }
    return true;
}

std::filesystem::path from_utf8(std::string_view text) {
    return std::filesystem::path{std::u8string{text.begin(), text.end()}};
}

std::string to_display_string(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return std::string{text.begin(), text.end()};
}

std::string host_env(const char* name) {
#ifdef _WIN32
    // Ask the OS, not the CRT: the CRT keeps its own copy of the environment that
    // SetEnvironmentVariableW (used by embedding hosts) does not update, and getenv is
    // ANSI-codepage besides.
    const std::wstring wide_name = from_utf8(name).native();
    const DWORD needed = GetEnvironmentVariableW(wide_name.c_str(), nullptr, 0);
    if (needed == 0) {
        return {};
    }
    std::vector<wchar_t> buffer(needed);
    if (GetEnvironmentVariableW(wide_name.c_str(), buffer.data(), needed) == 0) {
        return {};
    }
    const auto utf8 = std::filesystem::path{buffer.data()}.u8string();
    return std::string{utf8.begin(), utf8.end()};
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string{value};
#endif
}

} // namespace glaipnir::core
