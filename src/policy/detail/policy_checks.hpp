#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/c_policy.hpp"

namespace glaipnir::policy::detail {

inline constexpr std::uint64_t bytes_per_mb = 1024ull * 1024ull;

core::error_t policy_error(std::string message);

core::result_t<std::filesystem::path> expand_path(const std::string& text, const host_context_t& host);

core::result_t<std::filesystem::path> canonical_existing(const std::filesystem::path& path);

core::result_t<void> check_path_allowed(const std::filesystem::path& path, const host_context_t& host);

core::result_t<void> check_env_name(const std::string& name);

}
