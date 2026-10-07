#include "glaipnir/policy/c_policy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <format>
#include <fstream>
#include <set>
#include <sstream>
#include <system_error>

#include "glaipnir/core/c_sha256.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/policy/c_toml_reader.hpp"
#include "policy/detail/c_key_reader.hpp"
#include "policy/detail/net_rule_parser.hpp"
#include "policy/detail/policy_checks.hpp"
#include "policy/detail/toml_text.hpp"

using glaipnir::core::error_code;
using glaipnir::core::make_error;
using glaipnir::core::result_t;

glaipnir::policy::host_context_t glaipnir::policy::host_context_t::detect(std::filesystem::path state_root) {
    host_context_t host;
#ifdef _WIN32
    host.home = core::from_utf8(core::host_env("USERPROFILE"));
#else
    host.home = core::from_utf8(core::host_env("HOME"));
#endif
    std::error_code ec;
    if (!host.home.empty()) {
        auto canonical = std::filesystem::canonical(host.home, ec);
        host.home = core::normalize_path(ec ? host.home : canonical);
    }
    host.cwd = core::normalize_path(std::filesystem::current_path(ec));
    host.state_root = core::normalize_path(state_root);
    return host;
}

std::vector<std::filesystem::path> glaipnir::policy::sensitive_paths(const host_context_t& host) {
    if (host.home.empty()) {
        return {};
    }
    constexpr std::array<std::string_view, 24> relative{
        ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".config", ".netrc", ".npmrc", ".pypirc",
        ".git-credentials", ".claude", ".claude.json", ".codex", ".gemini", ".local/share/keyrings",
        "AppData/Roaming/Microsoft", "AppData/Local/Microsoft", "AppData/Roaming/GitHub CLI",
        "AppData/Local/Google", "AppData/Local/BraveSoftware", "AppData/Roaming/Mozilla",
        "AppData/Local/Packages", "Library/Keychains",
    };
    std::vector<std::filesystem::path> paths;
    paths.reserve(relative.size());
    for (const auto item : relative) {
        paths.push_back(core::normalize_path(host.home / core::from_utf8(item)));
    }
    return paths;
}

bool glaipnir::policy::looks_like_secret_name(std::string_view name) {
    std::string upper{name};
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    constexpr std::array<std::string_view, 11> markers{
        "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL", "API_KEY", "APIKEY",
        "ACCESS_KEY", "PRIVATE_KEY", "COOKIE",
    };
    for (const auto marker : markers) {
        if (upper.find(marker) != std::string::npos) {
            return true;
        }
    }
    return upper.ends_with("_KEY") || upper == "KEY";
}

std::string_view glaipnir::policy::to_string(isolation_backend backend) noexcept {
    switch (backend) {
    case isolation_backend::automatic: return "auto";
    case isolation_backend::app_container: return "app_container";
    case isolation_backend::windows_sandbox: return "windows_sandbox";
    case isolation_backend::process: return "process";
    case isolation_backend::firecracker: return "firecracker";
    }
    return "unknown";
}

std::string_view glaipnir::policy::to_string(network_mode mode) noexcept {
    switch (mode) {
    case network_mode::none: return "none";
    case network_mode::proxy: return "proxy";
    case network_mode::unrestricted: return "unrestricted";
    }
    return "unknown";
}

std::string_view glaipnir::policy::to_string(access_mode mode) noexcept {
    return mode == access_mode::read_write ? "read_write" : "read_only";
}

glaipnir::policy::c_policy glaipnir::policy::c_policy::deny_all() {
    return c_policy{policy_t{}};
}

result_t<glaipnir::policy::c_policy> glaipnir::policy::c_policy::load_file(const std::filesystem::path& file,
                                                                         const host_context_t& host) {
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        return make_error(error_code::not_found, "cannot open policy file " + core::to_display_string(file));
    }
    std::stringstream buffer;
    buffer << input.rdbuf();
    auto policy = parse(buffer.str(), host);
    if (!policy) {
        auto error = std::move(policy).error();
        error.message = core::to_display_string(file) + ": " + error.message;
        return error;
    }
    return policy;
}

result_t<glaipnir::policy::c_policy> glaipnir::policy::c_policy::parse(std::string_view text, const host_context_t& host) {
    auto reader = c_toml_reader::parse(text);
    if (!reader) {
        return std::move(reader).error();
    }
    detail::c_key_reader keys{*reader};
    policy_t data;

#define glaipnir_read(expr)                                                                                           \
    do {                                                                                                              \
        auto read_result = (expr);                                                                                    \
        if (!read_result) {                                                                                           \
            return std::move(read_result).error();                                                                    \
        }                                                                                                             \
    } while (false)

    glaipnir_read(keys.read("sandbox.name", data.name, "a string"));
    std::string backend_text{to_string(data.backend)};
    glaipnir_read(keys.read("sandbox.backend", backend_text, "a string"));
    auto backend = detail::parse_enum(backend_text,
                                      std::array{isolation_backend::automatic, isolation_backend::app_container,
                                                 isolation_backend::windows_sandbox, isolation_backend::process,
                                                 isolation_backend::firecracker},
                                      "backend");
    if (!backend) {
        return std::move(backend).error();
    }
    data.backend = *backend;
    glaipnir_read(keys.read("sandbox.less_privileged", data.less_privileged, "a boolean"));

    std::vector<std::string> read_paths;
    std::vector<std::string> write_paths;
    glaipnir_read(keys.read("filesystem.read", read_paths, "an array of strings"));
    glaipnir_read(keys.read("filesystem.write", write_paths, "an array of strings"));
    for (const auto& text_path : read_paths) {
        auto expanded = detail::expand_path(text_path, host);
        if (!expanded) {
            return std::move(expanded).error();
        }
        data.paths.push_back({*expanded, access_mode::read_only});
    }
    for (const auto& text_path : write_paths) {
        auto expanded = detail::expand_path(text_path, host);
        if (!expanded) {
            return std::move(expanded).error();
        }
        data.paths.push_back({*expanded, access_mode::read_write});
    }

    std::string network_text{to_string(data.network)};
    glaipnir_read(keys.read("network.mode", network_text, "a string"));
    auto network = detail::parse_enum(network_text,
                                      std::array{network_mode::none, network_mode::proxy, network_mode::unrestricted},
                                      "network mode");
    if (!network) {
        return std::move(network).error();
    }
    data.network = *network;
    std::vector<std::string> allow;
    glaipnir_read(keys.read("network.allow", allow, "an array of strings"));
    for (const auto& item : allow) {
        auto rule = detail::parse_net_rule(item);
        if (!rule) {
            return std::move(rule).error();
        }
        data.net_rules.push_back(std::move(*rule));
    }

    glaipnir_read(keys.read("env.pass", data.env.pass, "an array of strings"));
    for (const auto& [name, value] : keys.take_table("env.set")) {
        const auto* text_value = std::get_if<std::string>(&value->data);
        if (text_value == nullptr) {
            return detail::policy_error(std::format("line {}: env.set.{} must be a string", value->line, name));
        }
        data.env.set.emplace_back(name, *text_value);
    }

    std::uint64_t memory_mb = data.limits.memory_bytes / detail::bytes_per_mb;
    std::uint64_t max_processes = data.limits.max_processes;
    std::uint64_t cpu_percent = data.limits.cpu_percent;
    glaipnir_read(keys.read_unsigned("limits.memory_mb", memory_mb));
    glaipnir_read(keys.read_unsigned("limits.max_processes", max_processes));
    glaipnir_read(keys.read_unsigned("limits.cpu_percent", cpu_percent));
    glaipnir_read(keys.read_unsigned("limits.wall_timeout_s", data.limits.wall_timeout_seconds));
    glaipnir_read(keys.read_unsigned("limits.cpu_timeout_s", data.limits.cpu_timeout_seconds));
    if (memory_mb > (1ull << 30) || max_processes > 1'000'000 || cpu_percent > 100) {
        return detail::policy_error("limits out of range (memory_mb <= 2^30, max_processes <= 1000000, cpu_percent <= 100)");
    }
    data.limits.memory_bytes = memory_mb * detail::bytes_per_mb;
    data.limits.max_processes = static_cast<std::uint32_t>(max_processes);
    data.limits.cpu_percent = static_cast<std::uint32_t>(cpu_percent);

    glaipnir_read(keys.read("capabilities.child_processes", data.capabilities.child_processes, "a boolean"));
    glaipnir_read(keys.read("capabilities.clipboard_read", data.capabilities.clipboard_read, "a boolean"));
    glaipnir_read(keys.read("capabilities.clipboard_write", data.capabilities.clipboard_write, "a boolean"));
    glaipnir_read(keys.read("capabilities.desktop_ui", data.capabilities.desktop_ui, "a boolean"));
#undef glaipnir_read

    auto unknown = keys.reject_unknown({"sandbox", "filesystem", "network", "env", "env.set", "limits", "capabilities"});
    if (!unknown) {
        return std::move(unknown).error();
    }
    return from_data(std::move(data), host);
}

result_t<glaipnir::policy::c_policy> glaipnir::policy::c_policy::from_data(policy_t data, const host_context_t& host) {
    if (data.name.empty() || data.name.size() > 128) {
        return detail::policy_error("sandbox.name must be 1-128 characters");
    }

    std::vector<path_rule_t> resolved;
    for (const auto& rule : data.paths) {
        if (!rule.path.is_absolute()) {
            return detail::policy_error("path '" + core::to_display_string(rule.path) + "' must be absolute");
        }
        auto canonical = detail::canonical_existing(rule.path);
        if (!canonical) {
            return std::move(canonical).error();
        }
        auto allowed = detail::check_path_allowed(*canonical, host);
        if (!allowed) {
            return std::move(allowed).error();
        }
        for (const auto& existing : resolved) {
            if (core::is_same_or_inside(existing.path, *canonical) && core::is_same_or_inside(*canonical, existing.path)) {
                return detail::policy_error("path '" + core::to_display_string(*canonical) + "' is listed more than once");
            }
        }
        resolved.push_back({*canonical, rule.access});
    }
    data.paths = std::move(resolved);

    if (data.network != network_mode::proxy && !data.net_rules.empty()) {
        return detail::policy_error("network.allow is only meaningful with network.mode = \"proxy\"");
    }
    if (data.network == network_mode::proxy && data.net_rules.empty()) {
        return detail::policy_error("network.mode = \"proxy\" needs at least one network.allow entry");
    }

    std::set<std::string> env_names;
    for (const auto& name : data.env.pass) {
        auto valid = detail::check_env_name(name);
        if (!valid) {
            return std::move(valid).error();
        }
        if (!env_names.insert(name).second) {
            return detail::policy_error("environment variable '" + name + "' is declared twice");
        }
    }
    for (const auto& [name, value] : data.env.set) {
        auto valid = detail::check_env_name(name);
        if (!valid) {
            return std::move(valid).error();
        }
        if (!env_names.insert(name).second) {
            return detail::policy_error("environment variable '" + name + "' is declared twice");
        }
        if (value.find('\0') != std::string::npos) {
            return detail::policy_error("environment variable '" + name + "' contains a NUL byte");
        }
    }
    return c_policy{std::move(data)};
}

std::string glaipnir::policy::c_policy::to_toml() const {
    using detail::quote_toml_string;
    std::string out;
    out += "[sandbox]\n";
    out += "name = " + quote_toml_string(data_.name) + "\n";
    out += std::format("backend = \"{}\"\n", to_string(data_.backend));
    out += std::format("less_privileged = {}\n", data_.less_privileged);

    out += "\n[filesystem]\n";
    for (const auto mode : {access_mode::read_only, access_mode::read_write}) {
        out += mode == access_mode::read_only ? "read = [" : "write = [";
        bool first = true;
        for (const auto& rule : data_.paths) {
            if (rule.access == mode) {
                out += first ? "" : ", ";
                out += quote_toml_string(core::to_display_string(rule.path));
                first = false;
            }
        }
        out += "]\n";
    }

    out += "\n[network]\n";
    out += std::format("mode = \"{}\"\n", to_string(data_.network));
    out += "allow = [";
    for (std::size_t i = 0; i < data_.net_rules.size(); ++i) {
        out += i == 0 ? "" : ", ";
        out += quote_toml_string(std::format("{}:{}", data_.net_rules[i].host_pattern, data_.net_rules[i].port));
    }
    out += "]\n";

    out += "\n[env]\npass = [";
    for (std::size_t i = 0; i < data_.env.pass.size(); ++i) {
        out += i == 0 ? "" : ", ";
        out += quote_toml_string(data_.env.pass[i]);
    }
    out += "]\n\n[env.set]\n";
    for (const auto& [name, value] : data_.env.set) {
        out += quote_toml_string(name) + " = " + quote_toml_string(value) + "\n";
    }

    out += "\n[limits]\n";
    out += std::format("memory_mb = {}\n", data_.limits.memory_bytes / detail::bytes_per_mb);
    out += std::format("max_processes = {}\n", data_.limits.max_processes);
    out += std::format("cpu_percent = {}\n", data_.limits.cpu_percent);
    out += std::format("wall_timeout_s = {}\n", data_.limits.wall_timeout_seconds);
    out += std::format("cpu_timeout_s = {}\n", data_.limits.cpu_timeout_seconds);

    out += "\n[capabilities]\n";
    out += std::format("child_processes = {}\n", data_.capabilities.child_processes);
    out += std::format("clipboard_read = {}\n", data_.capabilities.clipboard_read);
    out += std::format("clipboard_write = {}\n", data_.capabilities.clipboard_write);
    out += std::format("desktop_ui = {}\n", data_.capabilities.desktop_ui);
    return out;
}

std::string glaipnir::policy::c_policy::digest() const {
    return core::c_sha256::hex_digest(to_toml());
}
