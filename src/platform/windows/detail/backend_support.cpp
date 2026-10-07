#include "platform/windows/detail/backend_support.hpp"

std::string glaipnir::platform::windows::detail::container_moniker(std::string_view session_id) {
    return "glaipnir." + std::string{session_id};
}

std::string_view glaipnir::platform::windows::detail::outcome_name(grant_outcome outcome) {
    switch (outcome) {
    case grant_outcome::unchanged: return "unchanged";
    case grant_outcome::granted: return "granted";
    case grant_outcome::already_allowed: return "already_allowed";
    }
    return "unknown";
}
