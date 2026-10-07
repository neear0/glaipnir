#pragma once

#include <array>
#include <string_view>

#include "glaipnir/core/error.hpp"
#include "glaipnir/platform/windows/c_unique_handle.hpp"
#include "platform/windows/detail/win_util.hpp"

namespace glaipnir::platform::windows::detail
{
	inline constexpr std::array<std::string_view, 3> restricted_baseline_sids{
		"S-1-1-0",
		"S-1-5-32-545",
		"S-1-5-12",
	};

	core::result_t<c_unique_handle> create_restricted_token(PSID sandbox_sid);
}
