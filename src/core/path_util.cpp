#include "glaipnir/core/path_util.hpp"

#include <cstdlib>

#include "core/detail/path_compare.hpp"

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

std::filesystem::path glaipnir::core::normalize_path(const std::filesystem::path& path) {
    auto normal = path.lexically_normal();
    if (!normal.has_filename() && normal.has_relative_path()) {
        normal = normal.parent_path();
    }
    return normal;
}

bool glaipnir::core::is_same_or_inside(const std::filesystem::path& child, const std::filesystem::path& parent) {
    const auto child_normal = normalize_path(child);
    const auto parent_normal = normalize_path(parent);
    auto child_it = child_normal.begin();
    for (auto parent_it = parent_normal.begin(); parent_it != parent_normal.end(); ++parent_it, ++child_it) {
        if (child_it == child_normal.end()) {
            return false;
        }
        if (parent_it->has_root_directory() && child_it->has_root_directory() && parent_it->native().size() == 1) {
            continue;
        }
        if (!detail::component_equal(*child_it, *parent_it)) {
            return false;
        }
    }
    return true;
}

std::filesystem::path glaipnir::core::from_utf8(std::string_view text) {
    return std::filesystem::path{std::u8string{text.begin(), text.end()}};
}

std::string glaipnir::core::to_display_string(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return std::string{text.begin(), text.end()};
}

std::string glaipnir::core::host_env(const char* name) {
#ifdef _WIN32
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
