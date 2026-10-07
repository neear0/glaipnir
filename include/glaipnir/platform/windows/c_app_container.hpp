#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows {

/// A per-session AppContainer profile and its package SID.
///
/// Each session gets its own moniker ("glaipnir.<session_id>"), so sessions receive distinct
/// SIDs and cannot touch each other's workspaces even though they run as the same user.
/// Creating a profile needs no administrator rights.
class c_app_container {
public:
    /// Creates the profile, or opens it when it already exists.
    static core::result_t<c_app_container> create_or_open(std::string_view moniker);

    /// Deletes the profile and its private folder. Missing profiles are not an error.
    static core::result_t<void> remove(std::string_view moniker);

    /// The package SID (PSID), valid for this object's lifetime.
    void* sid() const noexcept { return sid_.get(); }
    /// SID in "S-1-15-2-..." form.
    const std::string& sid_string() const noexcept { return sid_string_; }
    const std::string& moniker() const noexcept { return moniker_; }

    /// The container's private folder (%LOCALAPPDATA%\Packages\<moniker>\AC).
    core::result_t<std::filesystem::path> folder() const;

private:
    struct sid_deleter_t {
        void operator()(void* sid) const noexcept;
    };

    c_app_container(std::string moniker, void* sid, std::string sid_string)
        : moniker_(std::move(moniker)), sid_(sid), sid_string_(std::move(sid_string)) {}

    std::string moniker_;
    std::unique_ptr<void, sid_deleter_t> sid_;
    std::string sid_string_;
};

} // namespace glaipnir::platform::windows
