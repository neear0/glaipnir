#pragma once

#include <filesystem>

#include "glaipnir/core/error.hpp"
#include "glaipnir/persistence/safe_fs.hpp"

namespace glaipnir::persistence::detail {

core::result_t<void> copy_directory_contents(const std::filesystem::path& source, const std::filesystem::path& destination,
                                             tree_stats_t& stats);

core::result_t<void> measure_directory(const std::filesystem::path& root, tree_stats_t& stats);

core::result_t<void> remove_directory_tree(const std::filesystem::path& root);

}
