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

namespace glaipnir::policy {

using core::error_code;
using core::make_error;
using core::result_t;

namespace fs = std::filesystem;

namespace {

constexpr std::uint64_t bytes_per_mb = 1024ull * 1024ull;

core::error_t policy_error(std::string message) {
    return make_error(error_code::invalid_policy, std::move(message));
}

/// Typed access to parsed TOML that remembers which keys were read, so anything left over
/// can be reported as unknown. A misspelled key silently ignored is how policies end up
/// weaker (or stranger) than their author believed.
class c_key_reader {
public:
    explicit c_key_reader(const c_toml_reader& reader) : reader_(reader) {}

    const toml_value_t* find(const std::string& key) {
        const auto it = reader_.entries().find(key);
        if (it == reader_.entries().end()) {
            return nullptr;
        }
        used_.insert(key);
        return &it->second;
    }

    template <typename value_type>
    result_t<bool> read(const std::string& key, value_type& out, std::string_view type_name) {
        const auto* value = find(key);
        if (value == nullptr) {
            return false;
        }
        const auto* typed = std::get_if<value_type>(&value->data);
        if (typed == nullptr) {
            return policy_error(std::format("line {}: '{}' must be {}", value->line, key, type_name));
        }
        out = *typed;
        return true;
    }

    result_t<bool> read_unsigned(const std::string& key, std::uint64_t& out) {
        std::int64_t raw = 0;
        auto found = read(key, raw, "an integer");
        if (!found || !*found) {
            return found;
        }
        if (raw < 0) {
            return policy_error("'" + key + "' must not be negative");
        }
        out = static_cast<std::uint64_t>(raw);
        return true;
    }

    /// Keys under `table.` that nobody read, i.e. user-defined maps like [env.set].
    std::vector<std::pair<std::string, const toml_value_t*>> take_table(const std::string& table) {
        std::vector<std::pair<std::string, const toml_value_t*>> items;
        const std::string prefix = table + ".";
        for (const auto& [key, value] : reader_.entries()) {
            if (key.starts_with(prefix) && key.find('.', prefix.size()) == std::string::npos) {
                used_.insert(key);
                items.emplace_back(key.substr(prefix.size()), &value);
            }
        }
        return items;
    }

    result_t<void> reject_unknown(const std::set<std::string>& known_tables) const {
        for (const auto& [key, value] : reader_.entries()) {
            if (!used_.contains(key)) {
                return policy_error(std::format("line {}: unknown policy key '{}'", value.line, key));
            }
        }
        for (const auto& table : reader_.tables()) {
            if (!known_tables.contains(table)) {
                return policy_error("unknown policy table [" + table + "]");
            }
        }
        return core::ok();
    }

private:
    const c_toml_reader& reader_;
    std::set<std::string> used_;
};

template <typename enum_type, std::size_t count>
result_t<enum_type> parse_enum(std::string_view text, const std::array<enum_type, count>& values, std::string_view what) {
    std::string allowed;
    for (const auto value : values) {
        if (to_string(value) == text) {
            return value;
        }
        allowed += allowed.empty() ? "" : ", ";
        allowed += to_string(value);
    }
    return policy_error(std::format("unknown {} '{}' (expected one of: {})", what, text, allowed));
}

result_t<fs::path> expand_path(const std::string& text, const host_context_t& host) {
    fs::path expanded;
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

// Canonicalizing resolves symlinks and junctions, so the checks below judge the real target
// and a link named "project" cannot smuggle in the home directory.
result_t<fs::path> canonical_existing(const fs::path& path) {
    std::error_code ec;
    auto canonical = fs::canonical(path, ec);
    if (ec) {
        return policy_error("path '" + core::to_display_string(path) + "' cannot be resolved: " + ec.message());
    }
    return core::normalize_path(canonical);
}

result_t<void> check_path_allowed(const fs::path& path, const host_context_t& host) {
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

result_t<void> check_env_name(const std::string& name) {
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

bool is_hostname_label(std::string_view label) {
    if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
        return false;
    }
    return std::all_of(label.begin(), label.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    });
}

result_t<net_rule_t> parse_net_rule(const std::string& text) {
    net_rule_t rule;
    std::string host = text;
    const auto colon = text.rfind(':');
    if (colon != std::string::npos) {
        host = text.substr(0, colon);
        const auto port_text = text.substr(colon + 1);
        int port = 0;
        if (port_text.empty() || port_text.size() > 5 ||
            !std::all_of(port_text.begin(), port_text.end(), [](char c) { return c >= '0' && c <= '9'; }) ||
            (port = std::stoi(port_text)) < 1 || port > 65535) {
            return policy_error("network rule '" + text + "' has an invalid port");
        }
        rule.port = static_cast<std::uint16_t>(port);
    }
    std::string_view rest = host;
    if (rest.starts_with("*.")) {
        rest.remove_prefix(2);
    }
    if (rest.empty() || rest.size() > 253) {
        return policy_error("network rule '" + text + "' has an invalid host name");
    }
    std::string_view last_label;
    std::size_t start = 0;
    while (true) {
        const auto dot = rest.find('.', start);
        const auto label = rest.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
        if (!is_hostname_label(label)) {
            return policy_error("network rule '" + text + "': host names are lowercase letters, digits, '-' and '.'");
        }
        last_label = label;
        if (dot == std::string_view::npos) {
            break;
        }
        start = dot + 1;
    }
    // IP literals would bypass name-based filtering and make metadata endpoints reachable.
    if (std::all_of(last_label.begin(), last_label.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return policy_error("network rule '" + text + "': IP addresses are not allowed, use host names");
    }
    rule.host_pattern = host;
    return rule;
}

std::string toml_string(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    out += '"';
    return out;
}

} // namespace

host_context_t host_context_t::detect(fs::path state_root) {
    host_context_t host;
#ifdef _WIN32
    host.home = core::from_utf8(core::host_env("USERPROFILE"));
#else
    host.home = core::from_utf8(core::host_env("HOME"));
#endif
    std::error_code ec;
    if (!host.home.empty()) {
        auto canonical = fs::canonical(host.home, ec);
        host.home = core::normalize_path(ec ? host.home : canonical);
    }
    host.cwd = core::normalize_path(fs::current_path(ec));
    host.state_root = core::normalize_path(state_root);
    return host;
}

std::vector<fs::path> sensitive_paths(const host_context_t& host) {
    if (host.home.empty()) {
        return {};
    }
    // Best-effort list of well-known secret stores. Home itself is already forbidden; this list
    // exists so that granting a *subdirectory* of home cannot reach these either.
    constexpr std::array<std::string_view, 24> relative{
        ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".config", ".netrc", ".npmrc", ".pypirc",
        ".git-credentials", ".claude", ".claude.json", ".codex", ".gemini", ".local/share/keyrings",
        "AppData/Roaming/Microsoft", "AppData/Local/Microsoft", "AppData/Roaming/GitHub CLI",
        "AppData/Local/Google", "AppData/Local/BraveSoftware", "AppData/Roaming/Mozilla",
        "AppData/Local/Packages", "Library/Keychains",
    };
    std::vector<fs::path> paths;
    paths.reserve(relative.size());
    for (const auto item : relative) {
        paths.push_back(core::normalize_path(host.home / core::from_utf8(item)));
    }
    return paths;
}

bool looks_like_secret_name(std::string_view name) {
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

std::string_view to_string(isolation_backend backend) noexcept {
    switch (backend) {
    case isolation_backend::automatic: return "auto";
    case isolation_backend::app_container: return "app_container";
    case isolation_backend::windows_sandbox: return "windows_sandbox";
    case isolation_backend::process: return "process";
    case isolation_backend::firecracker: return "firecracker";
    }
    return "unknown";
}

std::string_view to_string(network_mode mode) noexcept {
    switch (mode) {
    case network_mode::none: return "none";
    case network_mode::proxy: return "proxy";
    case network_mode::unrestricted: return "unrestricted";
    }
    return "unknown";
}

std::string_view to_string(access_mode mode) noexcept {
    return mode == access_mode::read_write ? "read_write" : "read_only";
}

c_policy c_policy::deny_all() {
    return c_policy{policy_t{}};
}

result_t<c_policy> c_policy::load_file(const fs::path& file, const host_context_t& host) {
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

result_t<c_policy> c_policy::parse(std::string_view text, const host_context_t& host) {
    auto reader = c_toml_reader::parse(text);
    if (!reader) {
        return std::move(reader).error();
    }
    c_key_reader keys{*reader};
    policy_t data;

    // Each read returns result_t<bool>; a failed read aborts with its error.
#define glaipnir_read(expr)                                                                                           \
    do {                                                                                                              \
        auto read_result = (expr);                                                                                    \
        if (!read_result) {                                                                                           \
            return std::move(read_result).error();                                                                    \
        }                                                                                                             \
    } while (false)

    glaipnir_read(keys.read(std::string{"sandbox.name"}, data.name, "a string"));
    std::string backend_text{to_string(data.backend)};
    glaipnir_read(keys.read(std::string{"sandbox.backend"}, backend_text, "a string"));
    auto backend = parse_enum(backend_text,
                              std::array{isolation_backend::automatic, isolation_backend::app_container,
                                         isolation_backend::windows_sandbox, isolation_backend::process,
                                         isolation_backend::firecracker},
                              "backend");
    if (!backend) {
        return std::move(backend).error();
    }
    data.backend = *backend;
    glaipnir_read(keys.read(std::string{"sandbox.less_privileged"}, data.less_privileged, "a boolean"));

    std::vector<std::string> read_paths;
    std::vector<std::string> write_paths;
    glaipnir_read(keys.read(std::string{"filesystem.read"}, read_paths, "an array of strings"));
    glaipnir_read(keys.read(std::string{"filesystem.write"}, write_paths, "an array of strings"));
    for (const auto& text_path : read_paths) {
        auto expanded = expand_path(text_path, host);
        if (!expanded) {
            return std::move(expanded).error();
        }
        data.paths.push_back({*expanded, access_mode::read_only});
    }
    for (const auto& text_path : write_paths) {
        auto expanded = expand_path(text_path, host);
        if (!expanded) {
            return std::move(expanded).error();
        }
        data.paths.push_back({*expanded, access_mode::read_write});
    }

    std::string network_text{to_string(data.network)};
    glaipnir_read(keys.read(std::string{"network.mode"}, network_text, "a string"));
    auto network = parse_enum(network_text,
                              std::array{network_mode::none, network_mode::proxy, network_mode::unrestricted},
                              "network mode");
    if (!network) {
        return std::move(network).error();
    }
    data.network = *network;
    std::vector<std::string> allow;
    glaipnir_read(keys.read(std::string{"network.allow"}, allow, "an array of strings"));
    for (const auto& item : allow) {
        auto rule = parse_net_rule(item);
        if (!rule) {
            return std::move(rule).error();
        }
        data.net_rules.push_back(std::move(*rule));
    }

    glaipnir_read(keys.read(std::string{"env.pass"}, data.env.pass, "an array of strings"));
    for (const auto& [name, value] : keys.take_table("env.set")) {
        const auto* text_value = std::get_if<std::string>(&value->data);
        if (text_value == nullptr) {
            return policy_error(std::format("line {}: env.set.{} must be a string", value->line, name));
        }
        data.env.set.emplace_back(name, *text_value);
    }

    std::uint64_t memory_mb = data.limits.memory_bytes / bytes_per_mb;
    std::uint64_t max_processes = data.limits.max_processes;
    std::uint64_t cpu_percent = data.limits.cpu_percent;
    glaipnir_read(keys.read_unsigned("limits.memory_mb", memory_mb));
    glaipnir_read(keys.read_unsigned("limits.max_processes", max_processes));
    glaipnir_read(keys.read_unsigned("limits.cpu_percent", cpu_percent));
    glaipnir_read(keys.read_unsigned("limits.wall_timeout_s", data.limits.wall_timeout_seconds));
    glaipnir_read(keys.read_unsigned("limits.cpu_timeout_s", data.limits.cpu_timeout_seconds));
    if (memory_mb > (1ull << 30) || max_processes > 1'000'000 || cpu_percent > 100) {
        return policy_error("limits out of range (memory_mb <= 2^30, max_processes <= 1000000, cpu_percent <= 100)");
    }
    data.limits.memory_bytes = memory_mb * bytes_per_mb;
    data.limits.max_processes = static_cast<std::uint32_t>(max_processes);
    data.limits.cpu_percent = static_cast<std::uint32_t>(cpu_percent);

    glaipnir_read(keys.read(std::string{"capabilities.child_processes"}, data.capabilities.child_processes, "a boolean"));
    glaipnir_read(keys.read(std::string{"capabilities.clipboard_read"}, data.capabilities.clipboard_read, "a boolean"));
    glaipnir_read(keys.read(std::string{"capabilities.clipboard_write"}, data.capabilities.clipboard_write, "a boolean"));
    glaipnir_read(keys.read(std::string{"capabilities.desktop_ui"}, data.capabilities.desktop_ui, "a boolean"));
#undef glaipnir_read

    auto unknown = keys.reject_unknown({"sandbox", "filesystem", "network", "env", "env.set", "limits", "capabilities"});
    if (!unknown) {
        return std::move(unknown).error();
    }
    return from_data(std::move(data), host);
}

result_t<c_policy> c_policy::from_data(policy_t data, const host_context_t& host) {
    if (data.name.empty() || data.name.size() > 128) {
        return policy_error("sandbox.name must be 1-128 characters");
    }

    std::vector<path_rule_t> resolved;
    for (const auto& rule : data.paths) {
        if (!rule.path.is_absolute()) {
            return policy_error("path '" + core::to_display_string(rule.path) + "' must be absolute");
        }
        auto canonical = canonical_existing(rule.path);
        if (!canonical) {
            return std::move(canonical).error();
        }
        auto allowed = check_path_allowed(*canonical, host);
        if (!allowed) {
            return std::move(allowed).error();
        }
        for (const auto& existing : resolved) {
            if (core::is_same_or_inside(existing.path, *canonical) && core::is_same_or_inside(*canonical, existing.path)) {
                return policy_error("path '" + core::to_display_string(*canonical) + "' is listed more than once");
            }
        }
        resolved.push_back({*canonical, rule.access});
    }
    data.paths = std::move(resolved);

    if (data.network != network_mode::proxy && !data.net_rules.empty()) {
        return policy_error("network.allow is only meaningful with network.mode = \"proxy\"");
    }
    if (data.network == network_mode::proxy && data.net_rules.empty()) {
        return policy_error("network.mode = \"proxy\" needs at least one network.allow entry");
    }

    std::set<std::string> env_names;
    for (const auto& name : data.env.pass) {
        auto valid = check_env_name(name);
        if (!valid) {
            return std::move(valid).error();
        }
        if (!env_names.insert(name).second) {
            return policy_error("environment variable '" + name + "' is declared twice");
        }
    }
    for (const auto& [name, value] : data.env.set) {
        auto valid = check_env_name(name);
        if (!valid) {
            return std::move(valid).error();
        }
        if (!env_names.insert(name).second) {
            return policy_error("environment variable '" + name + "' is declared twice");
        }
        if (value.find('\0') != std::string::npos) {
            return policy_error("environment variable '" + name + "' contains a NUL byte");
        }
    }
    return c_policy{std::move(data)};
}

std::string c_policy::to_toml() const {
    std::string out;
    out += "[sandbox]\n";
    out += "name = " + toml_string(data_.name) + "\n";
    out += std::format("backend = \"{}\"\n", to_string(data_.backend));
    out += std::format("less_privileged = {}\n", data_.less_privileged);

    out += "\n[filesystem]\n";
    for (const auto mode : {access_mode::read_only, access_mode::read_write}) {
        out += mode == access_mode::read_only ? "read = [" : "write = [";
        bool first = true;
        for (const auto& rule : data_.paths) {
            if (rule.access == mode) {
                out += first ? "" : ", ";
                out += toml_string(core::to_display_string(rule.path));
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
        out += toml_string(std::format("{}:{}", data_.net_rules[i].host_pattern, data_.net_rules[i].port));
    }
    out += "]\n";

    out += "\n[env]\npass = [";
    for (std::size_t i = 0; i < data_.env.pass.size(); ++i) {
        out += i == 0 ? "" : ", ";
        out += toml_string(data_.env.pass[i]);
    }
    out += "]\n\n[env.set]\n";
    for (const auto& [name, value] : data_.env.set) {
        out += toml_string(name) + " = " + toml_string(value) + "\n";
    }

    out += "\n[limits]\n";
    out += std::format("memory_mb = {}\n", data_.limits.memory_bytes / bytes_per_mb);
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

std::string c_policy::digest() const {
    return core::c_sha256::hex_digest(to_toml());
}

} // namespace glaipnir::policy
