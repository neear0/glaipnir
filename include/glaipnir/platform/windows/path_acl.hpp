#pragma once

#include <filesystem>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::platform::windows {

/// Outcome of trying to make a path reachable for a container SID.
enum class grant_outcome {
    unchanged,       ///< an identical explicit grant was already present
    granted,         ///< the DACL was rewritten
    already_allowed, ///< not writable by us, but a package-wide ACE already allows the access
};

/// Gives `sid` exactly `access` on `path` (inherited by children when `path` is a directory).
///
/// Any previous explicit grant for the same SID is replaced, so downgrading a rule from
/// read_write to read_only really removes write access. Write grants never include WRITE_DAC
/// or WRITE_OWNER, so the sandbox cannot re-grant its files to others.
/// @param less_privileged when true, ALL APPLICATION PACKAGES ACEs do not count as access (LPAC)
core::result_t<grant_outcome> grant_path_access(const std::filesystem::path& path, void* sid, policy::access_mode access,
                                                bool less_privileged);

/// Removes every explicit ACE for `sid` from `path` (and, by inheritance, its children).
core::result_t<void> revoke_path_access(const std::filesystem::path& path, void* sid);

} // namespace glaipnir::platform::windows
