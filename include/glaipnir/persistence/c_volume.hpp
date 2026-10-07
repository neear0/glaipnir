#pragma once

#include <filesystem>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/persistence/persistence_types.hpp"

namespace glaipnir::persistence {

/// A session's durable workspace plus its named snapshots.
///
/// Layout under `root`:
///   workspace/            the only directory the sandbox can write by default
///   snapshots/<label>/    data/ (copy of workspace) + checkpoint.toml
///
/// Snapshots are full copies made without following links. That is slower than overlay/ZFS
/// CoW but works on every filesystem and every platform; CoW backends can slot in later behind
/// the same API. Callers must hold the session lock: copying a workspace that a live agent is
/// writing would capture a torn state.
class c_volume {
public:
    /// Opens the volume rooted at `root`, creating the directory structure if missing.
    static core::result_t<c_volume> open(std::filesystem::path root);

    /// The workspace directory exposed read-write to the sandbox.
    std::filesystem::path workspace() const { return root_ / "workspace"; }
    /// Root directory of this volume.
    const std::filesystem::path& root() const noexcept { return root_; }

    /// Copies the workspace into a new snapshot. Fails if `label` already exists.
    core::result_t<checkpoint_meta_t> snapshot(std::string_view label, std::string_view policy_digest) const;

    /// Replaces the workspace with the snapshot's contents. The snapshot itself is kept.
    /// The previous workspace is swapped out first, so a failed copy leaves it intact.
    core::result_t<void> rollback(std::string_view label) const;

    /// Lists snapshots, oldest first.
    core::result_t<std::vector<checkpoint_meta_t>> list_snapshots() const;

    /// Deletes one snapshot.
    core::result_t<void> remove_snapshot(std::string_view label) const;

    /// Copies workspace and snapshots into a new volume at `new_root`, which may exist but must
    /// not already contain a volume.
    core::result_t<c_volume> clone_to(const std::filesystem::path& new_root) const;

private:
    explicit c_volume(std::filesystem::path root) : root_(std::move(root)) {}

    std::filesystem::path snapshot_dir(std::string_view label) const;

    std::filesystem::path root_;
};

} // namespace glaipnir::persistence
