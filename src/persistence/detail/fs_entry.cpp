#include "persistence/detail/fs_entry.hpp"

#include "glaipnir/core/path_util.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

glaipnir::persistence::detail::entry_kind glaipnir::persistence::detail::classify(const std::filesystem::path& path,
                                                                                std::error_code& ec) {
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        ec = std::error_code(static_cast<int>(GetLastError()), std::system_category());
        return entry_kind::other;
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return entry_kind::other;
    }
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? entry_kind::directory : entry_kind::regular_file;
#else
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec) {
        return entry_kind::other;
    }
    if (std::filesystem::is_directory(status)) {
        return entry_kind::directory;
    }
    return std::filesystem::is_regular_file(status) ? entry_kind::regular_file : entry_kind::other;
#endif
}

glaipnir::core::error_t glaipnir::persistence::detail::io_failure(const std::string& what, const std::filesystem::path& path,
                                                                const std::error_code& ec) {
    return core::make_error(core::error_code::io_error, what + " " + core::to_display_string(path) + ": " + ec.message(),
                            ec.value());
}

void glaipnir::persistence::detail::make_writable(const std::filesystem::path& path) {
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) != 0) {
        SetFileAttributesW(path.c_str(), attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY));
    }
#else
    std::error_code ec;
    std::filesystem::permissions(path, std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::add | std::filesystem::perm_options::nofollow, ec);
#endif
}

glaipnir::core::result_t<void> glaipnir::persistence::detail::remove_entry(const std::filesystem::path& path) {
    make_writable(path);
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(path.c_str());
    const bool ok = (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                        ? RemoveDirectoryW(path.c_str()) != 0
                        : DeleteFileW(path.c_str()) != 0;
    if (!ok) {
        const auto ec = std::error_code(static_cast<int>(GetLastError()), std::system_category());
        return io_failure("cannot remove", path, ec);
    }
#else
    std::error_code ec;
    std::filesystem::remove(path, ec);
    if (ec) {
        return io_failure("cannot remove", path, ec);
    }
#endif
    return core::ok();
}
