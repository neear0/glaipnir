#include "policy/detail/net_rule_parser.hpp"

#include <algorithm>

#include "policy/detail/policy_checks.hpp"

bool glaipnir::policy::detail::is_hostname_label(std::string_view label) {
    if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
        return false;
    }
    return std::all_of(label.begin(), label.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    });
}

glaipnir::core::result_t<glaipnir::policy::net_rule_t> glaipnir::policy::detail::parse_net_rule(const std::string& text) {
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
    if (std::all_of(last_label.begin(), last_label.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return policy_error("network rule '" + text + "': IP addresses are not allowed, use host names");
    }
    rule.host_pattern = host;
    return rule;
}
