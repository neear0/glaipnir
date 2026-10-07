#pragma once

#include <format>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/c_toml_reader.hpp"
#include "policy/detail/policy_checks.hpp"

namespace glaipnir::policy::detail {

class c_key_reader {
public:
    explicit c_key_reader(const c_toml_reader& reader) : reader_(reader) {}

    const toml_value_t* find(const std::string& key);

    template <typename value_type>
    core::result_t<bool> read(const std::string& key, value_type& out, std::string_view type_name) {
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

    core::result_t<bool> read_unsigned(const std::string& key, std::uint64_t& out);

    std::vector<std::pair<std::string, const toml_value_t*>> take_table(const std::string& table);

    core::result_t<void> reject_unknown(const std::set<std::string>& known_tables) const;

private:
    const c_toml_reader& reader_;
    std::set<std::string> used_;
};

}
