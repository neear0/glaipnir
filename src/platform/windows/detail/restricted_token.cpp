#include "platform/windows/detail/restricted_token.hpp"

#include <cstdint>
#include <vector>

#include "platform/windows/detail/c_sid.hpp"
#include "platform/windows/detail/dacl.hpp"

glaipnir::core::result_t<glaipnir::platform::windows::c_unique_handle>
glaipnir::platform::windows::detail::create_restricted_token(PSID sandbox_sid)
{
	HANDLE raw_base = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(),
	                      TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &raw_base))
	{
		return last_error("cannot open process token");
	}
	c_unique_handle base{raw_base};

	DWORD length = 0;
	GetTokenInformation(base.get(), TokenGroups, nullptr, 0, &length);
	std::vector<std::uint8_t> groups_buffer(length);
	if (!GetTokenInformation(base.get(), TokenGroups, groups_buffer.data(), length, &length))
	{
		return last_error("cannot read token groups");
	}
	const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groups_buffer.data());
	PSID logon_sid = nullptr;
	for (DWORD i = 0; i < groups->GroupCount; ++i)
	{
		if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
		{
			logon_sid = groups->Groups[i].Sid;
		}
	}

	length = 0;
	GetTokenInformation(base.get(), TokenUser, nullptr, 0, &length);
	std::vector<std::uint8_t> user_buffer(length);
	if (!GetTokenInformation(base.get(), TokenUser, user_buffer.data(), length, &length))
	{
		return last_error("cannot read token user");
	}
	PSID user_sid = reinterpret_cast<const TOKEN_USER*>(user_buffer.data())->User.Sid;

	std::vector<c_sid> baseline;
	for (const auto text : restricted_baseline_sids)
	{
		auto sid = c_sid::from_string(text);
		if (!sid)
		{
			return std::move(sid).error();
		}
		baseline.push_back(std::move(*sid));
	}
	std::vector<SID_AND_ATTRIBUTES> restricting{{sandbox_sid, 0}};
	for (const auto& sid : baseline)
	{
		restricting.push_back({sid.get(), 0});
	}
	if (logon_sid != nullptr)
	{
		restricting.push_back({logon_sid, 0});
	}

	auto administrators = c_sid::from_string("S-1-5-32-544");
	if (!administrators)
	{
		return std::move(administrators).error();
	}
	SID_AND_ATTRIBUTES disabled{administrators->get(), 0};

	HANDLE raw_restricted = nullptr;
	if (!CreateRestrictedToken(base.get(), DISABLE_MAX_PRIVILEGE, 1, &disabled, 0, nullptr,
	                           static_cast<DWORD>(restricting.size()), restricting.data(), &raw_restricted))
	{
		return last_error("cannot create restricted token");
	}
	c_unique_handle restricted{raw_restricted};

	auto low = c_sid::from_string("S-1-16-4096");
	if (!low)
	{
		return std::move(low).error();
	}
	TOKEN_MANDATORY_LABEL label{};
	label.Label.Sid = low->get();
	label.Label.Attributes = SE_GROUP_INTEGRITY;
	if (!SetTokenInformation(restricted.get(), TokenIntegrityLevel, &label,
	                         sizeof(label) + GetLengthSid(low->get())))
	{
		return last_error("cannot lower token integrity");
	}

	auto system = c_sid::from_string("S-1-5-18");
	if (!system)
	{
		return std::move(system).error();
	}
	PSID trustees[] = {user_sid, system->get(), sandbox_sid};
	EXPLICIT_ACCESS_W entries[3]{};
	for (int i = 0; i < 3; ++i)
	{
		entries[i].grfAccessPermissions = GENERIC_ALL;
		entries[i].grfAccessMode = SET_ACCESS;
		entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		entries[i].Trustee.ptstrName = static_cast<LPWSTR>(trustees[i]);
	}
	PACL default_dacl = nullptr;
	const DWORD status = SetEntriesInAclW(3, entries, nullptr, &default_dacl);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot build default DACL", status);
	}
	local_ptr default_dacl_owner{default_dacl};
	TOKEN_DEFAULT_DACL token_dacl{default_dacl};
	if (!SetTokenInformation(restricted.get(), TokenDefaultDacl, &token_dacl, sizeof(token_dacl)))
	{
		return last_error("cannot set token default DACL");
	}
	return restricted;
}
