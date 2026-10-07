#include "persistence/detail/tree_walk.hpp"

#include <system_error>
#include <vector>

#include "persistence/detail/fs_entry.hpp"

glaipnir::core::result_t<void> glaipnir::persistence::detail::copy_directory_contents(const std::filesystem::path& source,
                                                                                    const std::filesystem::path& destination,
                                                                                    tree_stats_t& stats) {
    std::error_code ec;
    std::filesystem::directory_iterator it{source, ec};
    if (ec) {
        return io_failure("cannot list", source, ec);
    }
    for (const std::filesystem::directory_iterator end; it != end; it.increment(ec)) {
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
            std::filesystem::create_directory(to, ec);
            if (ec) {
                return io_failure("cannot create", to, ec);
            }
            ++stats.directories;
            auto nested = copy_directory_contents(from, to, stats);
            if (!nested) {
                return nested;
            }
        } else if (kind == entry_kind::regular_file) {
            std::filesystem::copy_file(from, to, std::filesystem::copy_options::none, ec);
            if (ec) {
                return io_failure("cannot copy", from, ec);
            }
            ++stats.files;
            stats.bytes += std::filesystem::file_size(to, ec);
            ec.clear();
        } else {
            stats.skipped.push_back(from);
        }
    }
    return core::ok();
}

glaipnir::core::result_t<void> glaipnir::persistence::detail::measure_directory(const std::filesystem::path& root,
                                                                              tree_stats_t& stats) {
    std::error_code ec;
    std::filesystem::directory_iterator it{root, ec};
    if (ec) {
        return io_failure("cannot list", root, ec);
    }
    for (const std::filesystem::directory_iterator end; it != end; it.increment(ec)) {
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
            stats.bytes += std::filesystem::file_size(it->path(), ec);
            ec.clear();
        } else {
            stats.skipped.push_back(it->path());
        }
    }
    return core::ok();
}

glaipnir::core::result_t<void> glaipnir::persistence::detail::remove_directory_tree(const std::filesystem::path& root) {
    std::error_code ec;
    std::vector<std::filesystem::path> children;
    for (std::filesystem::directory_iterator it{root, ec}, end; !ec && it != end; it.increment(ec)) {
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
