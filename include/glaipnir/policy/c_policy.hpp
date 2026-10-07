#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::policy {

/// Host facts that policy validation depends on. Injectable so tests never touch the real profile.
struct host_context_t {
    std::filesystem::path home;       ///< user profile / $HOME; never exposable
    std::filesystem::path cwd;        ///< expansion target for ${cwd}
    std::filesystem::path state_root; ///< glaipnir state; never exposable

    /// Reads the real home directory and working directory of this process.
    static host_context_t detect(std::filesystem::path state_root);
};

/// A validated, immutable sandbox policy.
///
/// Construction always goes through validation, so holding a c_policy means: every path exists,
/// is canonical, and avoids home/credential/state locations; no secret-looking variables are
/// injected; and network rules match the network mode.
class c_policy {
public:
    /// The empty policy: no paths, no network, no environment, no capabilities.
    static c_policy deny_all();

    /// Loads and validates a policy file.
    static core::result_t<c_policy> load_file(const std::filesystem::path& file, const host_context_t& host);

    /// Parses and validates policy TOML text.
    static core::result_t<c_policy> parse(std::string_view text, const host_context_t& host);

    /// Validates an already-built policy_t (paths are canonicalized in the returned copy).
    static core::result_t<c_policy> from_data(policy_t data, const host_context_t& host);

    /// The validated policy.
    const policy_t& data() const noexcept { return data_; }

    /// Canonical TOML rendering. Two equal policies render identically.
    std::string to_toml() const;

    /// SHA-256 of to_toml(); recorded in the audit log so every run names the exact policy used.
    std::string digest() const;

private:
    explicit c_policy(policy_t data) : data_(std::move(data)) {}

    policy_t data_;
};

/// True when an environment variable name looks like it carries a credential.
/// Such variables are never injected: credentials belong to the network proxy, not the sandbox.
bool looks_like_secret_name(std::string_view name);

/// Host locations that must never be exposed (credential stores, browser profiles, ...).
std::vector<std::filesystem::path> sensitive_paths(const host_context_t& host);

/// Textual names used in policy files and the canonical TOML.
std::string_view to_string(isolation_backend backend) noexcept;
std::string_view to_string(network_mode mode) noexcept;
std::string_view to_string(access_mode mode) noexcept;

} // namespace glaipnir::policy
