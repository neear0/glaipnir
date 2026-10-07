#include "policy/detail/policy_checks.hpp"

#include <algorithm>
#include <cctype>
#include <system_error>

#include "glaipnir/core/path_util.hpp"

glaipnir::core::error_t glaipnir::policy::detail::policy_error(std::string message) {
    return core::make_error(core::error_code::invalid_policy, std::move(message));
}

glaipnir::core::result_t<std::filesystem::path> glaipnir::policy::detail::expand_path(const std::string& text,
                                                                                     const host_context_t& host) {
    std::filesystem::path expanded;
    if (text.starts_with("${home}")) {
        expanded = host.home / core::from_utf8(std::string_view{text}.substr(7)).relative_path();
    } else if (text.starts_with("${cwd}")) {
        expanded = host.cwd / core::from_utf8(std::string_view{text}.substr(6)).relative_path();
    } else if (text.find("${") != std::string::npos) {
        return policy_error("path '" + text + "': only ${home} and ${cwd} are supported, and only as a prefix");
    } else {
        expanded = core::from_utf8(text);
    }
    if (!expanded.is_absolute()) {
        return policy_error("path '" + text + "' must be absolute (or start with ${cwd} / ${home})");
    }
    return expanded;
}

glaipnir::core::result_t<std::filesystem::path> glaipnir::policy::detail::canonical_existing(const std::filesystem::path& path) {
    std::error_code ec;
    auto canonical = std::filesystem::canonical(path, ec);
    if (ec) {
        return policy_error("path '" + core::to_display_string(path) + "' cannot be resolved: " + ec.message());
    }
    return core::normalize_path(canonical);
}

glaipnir::core::result_t<void> glaipnir::policy::detail::check_path_allowed(const std::filesystem::path& path,
                                                                           const host_context_t& host) {
    const auto shown = core::to_display_string(path);
    if (path == path.root_path() || !path.has_relative_path()) {
        return policy_error("path '" + shown + "' is a filesystem root; expose a specific directory instead");
    }
    if (!host.home.empty() && core::is_same_or_inside(host.home, path)) {
        return policy_error("path '" + shown + "' is the home directory or contains it; home is never exposed");
    }
    if (!host.state_root.empty() &&
        (core::is_same_or_inside(path, host.state_root) || core::is_same_or_inside(host.state_root, path))) {
        return policy_error("path '" + shown + "' overlaps the glaipnir state directory, which holds snapshots and audit logs");
    }
    for (const auto& sensitive : sensitive_paths(host)) {
        if (core::is_same_or_inside(path, sensitive) || core::is_same_or_inside(sensitive, path)) {
            return policy_error("path '" + shown + "' overlaps credential location '" +
                                core::to_display_string(sensitive) + "'");
        }
    }
    return core::ok();
}

glaipnir::core::result_t<void> glaipnir::policy::detail::check_env_name(const std::string& name) {
    if (name.empty() || name.size() > 255) {
        return policy_error("environment variable names must be 1-255 characters");
    }
    for (const char c : name) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x21 || u > 0x7e || c == '=') {
            return policy_error("environment variable name '" + name + "' contains an invalid character");
        }
    }
    std::string upper = name;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (upper.starts_with("GLAIPNIR_")) {
        return policy_error("environment variable '" + name + "' is reserved for glaipnir");
    }
    if (looks_like_secret_name(name)) {
        return policy_error("environment variable '" + name +
                            "' looks like a credential; secrets never enter the sandbox (use the network proxy's credential brokering)");
    }
    return core::ok();
}
