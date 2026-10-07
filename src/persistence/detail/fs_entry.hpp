#pragma once

#include <filesystem>
#include <string>
#include <system_error>

#include "glaipnir/core/error.hpp"

namespace glaipnir::persistence::detail {

enum class entry_kind { directory, regular_file, other };

entry_kind classify(const std::filesystem::path& path, std::error_code& ec);

core::error_t io_failure(const std::string& what, const std::filesystem::path& path, const std::error_code& ec);

void make_writable(const std::filesystem::path& path);

core::result_t<void> remove_entry(const std::filesystem::path& path);

}
