#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

#include "glaipnir/core/error.hpp"

namespace glaipnir::persistence {

/// What a tree operation touched.
struct tree_stats_t {
    std::uint64_t files = 0;
    std::uint64_t directories = 0;
    std::uint64_t bytes = 0;
    std::vector<std::filesystem::path> skipped; ///< links / reparse points / devices not followed
};

/// Copies a directory tree, following nothing.
///
/// Only regular files and real directories are copied; symlinks, junctions and other reparse
/// points are skipped and reported. The host side runs with the user's full rights, so following
/// a link the agent planted in its workspace would copy host secrets into a snapshot, and a later
/// rollback would hand them to the sandbox.
/// @param source      existing directory
/// @param destination must not exist yet
core::result_t<tree_stats_t> copy_tree(const std::filesystem::path& source, const std::filesystem::path& destination);

/// Deletes a directory tree without ever descending through a link. Links themselves are removed.
/// Clears read-only attributes first (git object files are read-only on Windows).
core::result_t<void> remove_tree(const std::filesystem::path& root);

/// Counts files and bytes under `root` without following links.
core::result_t<tree_stats_t> measure_tree(const std::filesystem::path& root);

} // namespace glaipnir::persistence
