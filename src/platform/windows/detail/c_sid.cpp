#include "platform/windows/detail/c_sid.hpp"

#include <sddl.h>

#include "glaipnir/core/c_sha256.hpp"

glaipnir::core::result_t<glaipnir::platform::windows::detail::c_sid>
glaipnir::platform::windows::detail::c_sid::from_string(std::string_view text)
{
	PSID sid = nullptr;
	if (!ConvertStringSidToSidW(to_wide(text).c_str(), &sid))
	{
		return last_error("invalid SID '" + std::string{text} + "'", core::error_code::invalid_argument);
	}
	auto copy = copy_of(sid);
	LocalFree(sid);
	return copy;
}

glaipnir::core::result_t<glaipnir::platform::windows::detail::c_sid>
glaipnir::platform::windows::detail::c_sid::copy_of(PSID sid)
{
	if (sid == nullptr || !IsValidSid(sid))
	{
		return core::make_error(core::error_code::invalid_argument, "invalid SID");
	}
	const DWORD length = GetLengthSid(sid);
	std::vector<std::uint8_t> bytes(length);
	if (!CopySid(length, bytes.data(), sid))
	{
		return last_error("cannot copy SID");
	}
	return c_sid{std::move(bytes)};
}

glaipnir::platform::windows::detail::c_sid
glaipnir::platform::windows::detail::c_sid::for_session(std::string_view session_key)
{
	core::c_sha256 hasher;
	hasher.update("glaipnir.session.");
	hasher.update(session_key);
	const auto digest = hasher.finish();

	constexpr BYTE sub_authority_count = 5;
	std::vector<std::uint8_t> bytes(GetSidLengthRequired(sub_authority_count));
	SID_IDENTIFIER_AUTHORITY authority = SECURITY_RESOURCE_MANAGER_AUTHORITY;
	InitializeSid(bytes.data(), &authority, sub_authority_count);
	for (BYTE i = 0; i < sub_authority_count; ++i)
	{
		*GetSidSubAuthority(bytes.data(), i) =
			(static_cast<DWORD>(digest[i * 4]) << 24) | (static_cast<DWORD>(digest[i * 4 + 1]) << 16) |
			(static_cast<DWORD>(digest[i * 4 + 2]) << 8) | static_cast<DWORD>(digest[i * 4 + 3]);
	}
	return c_sid{std::move(bytes)};
}

std::string glaipnir::platform::windows::detail::c_sid::to_string() const
{
	wchar_t* text = nullptr;
	if (!ConvertSidToStringSidW(get(), &text))
	{
		return {};
	}
	std::string result = from_wide(text);
	LocalFree(text);
	return result;
}
