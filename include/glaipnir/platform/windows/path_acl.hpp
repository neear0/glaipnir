#pragma once

#include <filesystem>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::platform::windows {

enum class grant_outcome {
    unchanged,
    granted,
    already_allowed,
};

core::result_t<grant_outcome> grant_path_access(const std::filesystem::path& path, void* sid, policy::access_mode access,
                                                bool less_privileged);

core::result_t<void> revoke_path_access(const std::filesystem::path& path, void* sid);

}
