#include "platform/windows/detail/dacl.hpp"

#include <sddl.h>

glaipnir::core::result_t<glaipnir::platform::windows::detail::dacl_t>
glaipnir::platform::windows::detail::read_dacl(const std::wstring& path)
{
	PACL dacl = nullptr;
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	const DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
	                                           nullptr,
	                                           &dacl, nullptr, &descriptor);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot read ACL of " + from_wide(path), status);
	}
	return dacl_t{local_ptr{descriptor}, dacl};
}

bool glaipnir::platform::windows::detail::has_exact_grant(PACL dacl, PSID sid, DWORD mask, BYTE flags)
{
	int matching = 0;
	for (DWORD i = 0; i < dacl->AceCount; ++i)
	{
		void* raw = nullptr;
		if (!GetAce(dacl, i, &raw))
		{
			return false;
		}
		const auto* header = static_cast<ACE_HEADER*>(raw);
		if ((header->AceFlags & INHERITED_ACE) != 0)
		{
			continue;
		}
		if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE)
		{
			continue;
		}
		auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
		if (!EqualSid(&ace->SidStart, sid))
		{
			continue;
		}
		if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Mask != mask ||
			(header->AceFlags & (inherit_flags | INHERIT_ONLY_ACE)) != flags)
		{
			return false;
		}
		++matching;
	}
	return matching == 1;
}

bool glaipnir::platform::windows::detail::has_any_explicit_ace(PACL dacl, PSID sid)
{
	for (DWORD i = 0; i < dacl->AceCount; ++i)
	{
		void* raw = nullptr;
		if (!GetAce(dacl, i, &raw))
		{
			return true;
		}
		const auto* header = static_cast<ACE_HEADER*>(raw);
		if ((header->AceFlags & INHERITED_ACE) == 0 &&
			(header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE) &&
			EqualSid(&static_cast<ACCESS_ALLOWED_ACE*>(raw)->SidStart, sid))
		{
			return true;
		}
	}
	return false;
}

bool glaipnir::platform::windows::detail::package_group_allows(PACL dacl, DWORD mask, bool less_privileged)
{
	PSID group = nullptr;
	if (!ConvertStringSidToSidW(less_privileged ? L"S-1-15-2-2" : L"S-1-15-2-1", &group))
	{
		return false;
	}
	local_ptr group_owner{group};
	for (DWORD i = 0; i < dacl->AceCount; ++i)
	{
		void* raw = nullptr;
		if (!GetAce(dacl, i, &raw))
		{
			return false;
		}
		const auto* header = static_cast<ACE_HEADER*>(raw);
		if (header->AceType == ACCESS_ALLOWED_ACE_TYPE && (header->AceFlags & INHERIT_ONLY_ACE) == 0)
		{
			const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
			if (EqualSid(const_cast<DWORD*>(&ace->SidStart), group) && (ace->Mask & mask) == mask)
			{
				return true;
			}
		}
	}
	return false;
}

glaipnir::core::result_t<void> glaipnir::platform::windows::detail::apply_entry(const std::wstring& path, PACL old_dacl,
	PSID sid, ACCESS_MODE mode, DWORD mask,
	DWORD inheritance)
{
	EXPLICIT_ACCESS_W entry{};
	entry.grfAccessPermissions = mask;
	entry.grfAccessMode = mode;
	entry.grfInheritance = inheritance;
	entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	entry.Trustee.ptstrName = static_cast<LPWSTR>(sid);

	PACL new_dacl = nullptr;
	DWORD status = SetEntriesInAclW(1, &entry, old_dacl, &new_dacl);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot build ACL for " + from_wide(path), status);
	}
	local_ptr new_dacl_owner{new_dacl};
	status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
	                               nullptr, new_dacl, nullptr);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot write ACL of " + from_wide(path), status);
	}
	return core::ok();
}
