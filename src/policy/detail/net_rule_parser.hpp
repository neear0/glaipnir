#pragma once

#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::policy::detail {

bool is_hostname_label(std::string_view label);

core::result_t<net_rule_t> parse_net_rule(const std::string& text);

}
