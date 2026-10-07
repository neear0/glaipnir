#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "platform/windows/detail/win_util.hpp"

namespace glaipnir::platform::windows::detail
{
	class c_sid
	{
	public:
		static core::result_t<c_sid> from_string(std::string_view text);

		static core::result_t<c_sid> copy_of(PSID sid);

		static c_sid for_session(std::string_view session_key);

		PSID get() const noexcept { return const_cast<std::uint8_t*>(bytes_.data()); }

		std::string to_string() const;

	private:
		explicit c_sid(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes))
		{
		}

		std::vector<std::uint8_t> bytes_;
	};
}
