#include "policy/detail/c_key_reader.hpp"

const glaipnir::policy::toml_value_t* glaipnir::policy::detail::c_key_reader::find(const std::string& key) {
    const auto it = reader_.entries().find(key);
    if (it == reader_.entries().end()) {
        return nullptr;
    }
    used_.insert(key);
    return &it->second;
}

glaipnir::core::result_t<bool> glaipnir::policy::detail::c_key_reader::read_unsigned(const std::string& key,
                                                                                    std::uint64_t& out) {
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

std::vector<std::pair<std::string, const glaipnir::policy::toml_value_t*>>
glaipnir::policy::detail::c_key_reader::take_table(const std::string& table) {
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

glaipnir::core::result_t<void>
glaipnir::policy::detail::c_key_reader::reject_unknown(const std::set<std::string>& known_tables) const {
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
