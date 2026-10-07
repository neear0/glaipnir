#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "glaipnir/platform/windows/path_acl.hpp"
#include "platform/windows/detail/win_util.hpp"

namespace glaipnir::platform::windows::detail {

inline constexpr unsigned timeout_exit_code = 124;
inline constexpr unsigned terminated_exit_code = 137;

struct well_known_sid_t {
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> bytes{};
};

std::string container_moniker(std::string_view session_id);

std::string_view outcome_name(grant_outcome outcome);

}
