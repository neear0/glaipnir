#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace glaipnir::persistence {

/// What a checkpoint captures, from cheapest to most complete.
enum class checkpoint_kind {
    filesystem, ///< workspace contents only (all platforms)
    process,    ///< + process memory via CRIU (Linux, not implemented yet)
    machine,    ///< + full VM RAM/CPU/disk via Firecracker or Hyper-V (not implemented yet)
};

/// A named, immutable copy of a session's workspace.
struct snapshot_info_t {
    std::string label;
    std::string created_at; ///< RFC 3339 UTC
    std::uint64_t files = 0;
    std::uint64_t bytes = 0;
    std::uint64_t skipped_links = 0; ///< links found in the workspace and deliberately not captured
};

/// Metadata stored next to every checkpoint so restore knows how to bring it back.
struct checkpoint_meta_t {
    snapshot_info_t snapshot;
    checkpoint_kind kind = checkpoint_kind::filesystem;
    std::string policy_digest; ///< policy in force when taken; restore re-applies the *current* policy anyway
};

/// Where a session lives and how it should be treated.
struct session_config_t {
    std::string session_id;
    std::filesystem::path state_root;
    bool ephemeral = false; ///< destroyed (workspace, container profile, grants) when the run ends
};

std::string_view to_string(checkpoint_kind kind) noexcept;

} // namespace glaipnir::persistence
