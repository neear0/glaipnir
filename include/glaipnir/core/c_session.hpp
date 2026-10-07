#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/c_audit_log.hpp"
#include "glaipnir/core/error.hpp"
#include "glaipnir/persistence/c_volume.hpp"
#include "glaipnir/persistence/persistence_types.hpp"
#include "glaipnir/platform/platform.hpp"

namespace glaipnir::core {

/// How c_session::open treats an existing / missing session.
enum class open_mode { create, open_existing, open_or_create };

/// A durable agent session: an id, a persistent workspace, snapshots and an audit trail.
///
/// An open c_session holds the session's exclusive lock, so at most one process can run in or
/// modify a session at a time. Layout under the state root:
///   sessions/<id>/   workspace, snapshots, grant ledger, lock
///   audit/<id>.log   hash-chained audit log (kept after the session is destroyed)
class c_session {
public:
    /// Opens or creates a session and takes its lock.
    static result_t<c_session> open(const persistence::session_config_t& config, open_mode mode);

    /// Ids of all sessions under `state_root`, sorted.
    static result_t<std::vector<std::string>> list(const std::filesystem::path& state_root);

    /// Deletes a session's workspace, snapshots, grants and container profile. Fails with
    /// `busy` while the session is running. The audit log is kept.
    static result_t<void> destroy(const std::filesystem::path& state_root, std::string_view session_id);

    /// Directory of a session (whether or not it exists).
    static std::filesystem::path directory_for(const std::filesystem::path& state_root, std::string_view session_id);
    /// Audit log path of a session.
    static std::filesystem::path audit_path_for(const std::filesystem::path& state_root, std::string_view session_id);

    const persistence::session_config_t& config() const noexcept { return config_; }
    const std::string& session_id() const noexcept { return config_.session_id; }
    std::filesystem::path directory() const { return directory_for(config_.state_root, config_.session_id); }
    const persistence::c_volume& volume() const noexcept { return volume_; }
    c_audit_log& audit() noexcept { return audit_; }

    /// Captures the workspace under `label`.
    result_t<persistence::checkpoint_meta_t> snapshot(std::string_view label, std::string_view policy_digest = {});

    /// Restores the workspace from `label`. Isolation rules are re-applied on the next run,
    /// never carried over from the snapshot.
    result_t<void> rollback(std::string_view label);

    /// Deletes snapshot `label`.
    result_t<void> remove_snapshot(std::string_view label);

    /// Snapshots of this session, oldest first.
    result_t<std::vector<persistence::checkpoint_meta_t>> snapshots() const;

    /// Copies workspace and snapshots into a new session `new_id` (which gets its own container
    /// identity and starts with no grants) and returns it opened.
    result_t<c_session> fork_session(std::string_view new_id);

private:
    c_session(persistence::session_config_t config, persistence::c_volume volume, c_audit_log audit,
              platform::c_session_lock lock);

    persistence::session_config_t config_;
    persistence::c_volume volume_;
    c_audit_log audit_;
    platform::c_session_lock lock_;
};

} // namespace glaipnir::core
