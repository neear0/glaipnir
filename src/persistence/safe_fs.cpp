#include "glaipnir/persistence/safe_fs.hpp"

#include <system_error>

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

namespace glaipnir::persistence {

using core::error_code;
using core::make_error;
using core::result_t;

namespace fs = std::filesystem;

namespace {

enum class entry_kind { directory, regular_file, other };

// std::filesystem reports junctions as a vendor-specific type on MSVC and other reparse points
// (cloud files, app exec links) inconsistently, so on Windows ask the OS directly.
entry_kind classify(const fs::path& path, std::error_code& ec) {
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
    const auto status = fs::symlink_status(path, ec);
    if (ec) {
        return entry_kind::other;
    }
    if (fs::is_directory(status)) {
        return entry_kind::directory;
    }
    return fs::is_regular_file(status) ? entry_kind::regular_file : entry_kind::other;
#endif
}

core::error_t io_failure(const std::string& what, const fs::path& path, const std::error_code& ec) {
    return make_error(error_code::io_error, what + " " + core::to_display_string(path) + ": " + ec.message(), ec.value());
}

result_t<void> copy_directory_contents(const fs::path& source, const fs::path& destination, tree_stats_t& stats) {
    std::error_code ec;
    fs::directory_iterator it{source, ec};
    if (ec) {
        return io_failure("cannot list", source, ec);
    }
    for (const fs::directory_iterator end; it != end; it.increment(ec)) {
        if (ec) {
            return io_failure("cannot list", source, ec);
        }
        const auto& from = it->path();
        const auto to = destination / from.filename();
        const auto kind = classify(from, ec);
        if (ec) {
            return io_failure("cannot inspect", from, ec);
        }
        if (kind == entry_kind::directory) {
            fs::create_directory(to, ec);
            if (ec) {
                return io_failure("cannot create", to, ec);
            }
            ++stats.directories;
            auto nested = copy_directory_contents(from, to, stats);
            if (!nested) {
                return nested;
            }
        } else if (kind == entry_kind::regular_file) {
            fs::copy_file(from, to, fs::copy_options::none, ec);
            if (ec) {
                return io_failure("cannot copy", from, ec);
            }
            ++stats.files;
            stats.bytes += fs::file_size(to, ec);
            ec.clear();
        } else {
            stats.skipped.push_back(from);
        }
    }
    return core::ok();
}

result_t<void> measure_directory(const fs::path& root, tree_stats_t& stats) {
    std::error_code ec;
    fs::directory_iterator it{root, ec};
    if (ec) {
        return io_failure("cannot list", root, ec);
    }
    for (const fs::directory_iterator end; it != end; it.increment(ec)) {
        if (ec) {
            return io_failure("cannot list", root, ec);
        }
        const auto kind = classify(it->path(), ec);
        if (ec) {
            return io_failure("cannot inspect", it->path(), ec);
        }
        if (kind == entry_kind::directory) {
            ++stats.directories;
            auto nested = measure_directory(it->path(), stats);
            if (!nested) {
                return nested;
            }
        } else if (kind == entry_kind::regular_file) {
            ++stats.files;
            stats.bytes += fs::file_size(it->path(), ec);
            ec.clear();
        } else {
            stats.skipped.push_back(it->path());
        }
    }
    return core::ok();
}

void make_writable(const fs::path& path) {
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) != 0) {
        SetFileAttributesW(path.c_str(), attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY));
    }
#else
    std::error_code ec;
    fs::permissions(path, fs::perms::owner_write, fs::perm_options::add | fs::perm_options::nofollow, ec);
#endif
}

// Removes a link or file entry itself. Directory links must go through remove_directory, or
// Windows refuses with "directory not empty" style errors even though nothing is followed.
result_t<void> remove_entry(const fs::path& path) {
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
    fs::remove(path, ec);
    if (ec) {
        return io_failure("cannot remove", path, ec);
    }
#endif
    return core::ok();
}

result_t<void> remove_directory_tree(const fs::path& root) {
    std::error_code ec;
    std::vector<fs::path> children;
    for (fs::directory_iterator it{root, ec}, end; !ec && it != end; it.increment(ec)) {
        children.push_back(it->path());
    }
    if (ec) {
        return io_failure("cannot list", root, ec);
    }
    for (const auto& child : children) {
        const auto kind = classify(child, ec);
        if (ec) {
            return io_failure("cannot inspect", child, ec);
        }
        auto removed = kind == entry_kind::directory ? remove_directory_tree(child) : remove_entry(child);
        if (!removed) {
            return removed;
        }
    }
    return remove_entry(root);
}

} // namespace

result_t<tree_stats_t> copy_tree(const fs::path& source, const fs::path& destination) {
    std::error_code ec;
    if (classify(source, ec) != entry_kind::directory) {
        return make_error(error_code::invalid_argument,
                          "copy source " + core::to_display_string(source) + " is not a plain directory");
    }
    if (fs::exists(fs::symlink_status(destination, ec))) {
        return make_error(error_code::already_exists, "copy destination " + core::to_display_string(destination) + " exists");
    }
    fs::create_directories(destination, ec);
    if (ec) {
        return io_failure("cannot create", destination, ec);
    }
    tree_stats_t stats;
    auto copied = copy_directory_contents(source, destination, stats);
    if (!copied) {
        return std::move(copied).error();
    }
    return stats;
}

result_t<void> remove_tree(const fs::path& root) {
    std::error_code ec;
    if (!fs::exists(fs::symlink_status(root, ec))) {
        return core::ok();
    }
    const auto kind = classify(root, ec);
    if (ec) {
        return io_failure("cannot inspect", root, ec);
    }
    return kind == entry_kind::directory ? remove_directory_tree(root) : remove_entry(root);
}

result_t<tree_stats_t> measure_tree(const fs::path& root) {
    tree_stats_t stats;
    auto measured = measure_directory(root, stats);
    if (!measured) {
        return std::move(measured).error();
    }
    return stats;
}

} // namespace glaipnir::persistence
