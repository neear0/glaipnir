#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"
#include "glaipnir/persistence/persistence_types.hpp"

namespace glaipnir::persistence::detail {

inline constexpr std::string_view meta_file_name = "checkpoint.toml";

std::string scratch_name(std::string_view purpose);

core::result_t<void> write_meta(const std::filesystem::path& file, const checkpoint_meta_t& meta);

core::result_t<checkpoint_meta_t> read_meta(const std::filesystem::path& file);

}
