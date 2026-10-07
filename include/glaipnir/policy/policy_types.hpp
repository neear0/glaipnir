#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace glaipnir::policy {

/// How a host path is exposed to the sandbox.
enum class access_mode { read_only, read_write };

/// Which isolation backend runs the sandbox.
enum class isolation_backend {
    automatic,       ///< strongest backend available on this host
    app_container,   ///< Windows AppContainer + Job Object
    windows_sandbox, ///< Windows Sandbox (Hyper-V); not implemented yet
    process,         ///< Linux Landlock + seccomp + namespaces; not implemented yet
    firecracker,     ///< Linux Firecracker microVM; not implemented yet
};

/// What network access the sandbox gets.
enum class network_mode {
    none,         ///< no network at all
    proxy,        ///< egress only via c_network_proxy, filtered by `net_rules`
    unrestricted, ///< direct internet access (no LAN); explicit opt-out of filtering
};

/// One host path the sandbox may reach. Paths are absolute and canonical after loading.
struct path_rule_t {
    std::filesystem::path path;
    access_mode access = access_mode::read_only;
};

/// One allowed egress destination. `host_pattern` is an exact name or "*.example.com".
struct net_rule_t {
    std::string host_pattern;
    std::uint16_t port = 443;
};

/// Resource ceilings. Zero means "no limit" for every field.
struct resource_limit_t {
    std::uint64_t memory_bytes = 4ull * 1024 * 1024 * 1024;
    std::uint32_t max_processes = 128;
    std::uint32_t cpu_percent = 100;
    std::uint64_t wall_timeout_seconds = 0;
    std::uint64_t cpu_timeout_seconds = 0;
};

/// Coarse permissions beyond filesystem and network. All denied unless the policy grants them.
struct capability_t {
    bool child_processes = false; ///< may spawn subprocesses (git, node, python, ...)
    bool clipboard_read = false;
    bool clipboard_write = false;
    bool desktop_ui = false;      ///< may touch windows, atoms and settings outside the sandbox
};

/// Environment the sandboxed process starts with; the host environment is never inherited.
struct env_policy_t {
    std::vector<std::string> pass;                           ///< names copied from the host
    std::vector<std::pair<std::string, std::string>> set;    ///< literal values
};

/// Complete, platform-neutral sandbox policy. Each backend translates it to native primitives.
struct policy_t {
    std::string name = "unnamed";
    isolation_backend backend = isolation_backend::automatic;
    bool less_privileged = false; ///< Windows LPAC; off by default because it cannot read Program Files
    std::vector<path_rule_t> paths;
    network_mode network = network_mode::none;
    std::vector<net_rule_t> net_rules;
    env_policy_t env;
    resource_limit_t limits;
    capability_t capabilities;
};

} // namespace glaipnir::policy
