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

enum class open_mode { create, open_existing, open_or_create };

class c_session {
public:
    static result_t<c_session> open(const persistence::session_config_t& config, open_mode mode);

    static result_t<std::vector<std::string>> list(const std::filesystem::path& state_root);

    static result_t<void> destroy(const std::filesystem::path& state_root, std::string_view session_id);

    static std::filesystem::path directory_for(const std::filesystem::path& state_root, std::string_view session_id);
    static std::filesystem::path audit_path_for(const std::filesystem::path& state_root, std::string_view session_id);

    const persistence::session_config_t& config() const noexcept { return config_; }
    const std::string& session_id() const noexcept { return config_.session_id; }
    std::filesystem::path directory() const { return directory_for(config_.state_root, config_.session_id); }
    const persistence::c_volume& volume() const noexcept { return volume_; }
    c_audit_log& audit() noexcept { return audit_; }

    result_t<persistence::checkpoint_meta_t> snapshot(std::string_view label, std::string_view policy_digest = {});

    result_t<void> rollback(std::string_view label);

    result_t<void> remove_snapshot(std::string_view label);

    result_t<std::vector<persistence::checkpoint_meta_t>> snapshots() const;

    result_t<c_session> fork_session(std::string_view new_id);

private:
    c_session(persistence::session_config_t config, persistence::c_volume volume, c_audit_log audit,
              platform::c_session_lock lock);

    persistence::session_config_t config_;
    persistence::c_volume volume_;
    c_audit_log audit_;
    platform::c_session_lock lock_;
};

}
