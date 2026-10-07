#include "platform/windows/detail/dacl.hpp"

#include <vector>

glaipnir::core::result_t<glaipnir::platform::windows::detail::dacl_t>
glaipnir::platform::windows::detail::read_dacl(const std::wstring& path)
{
	PACL dacl = nullptr;
	PSID owner = nullptr;
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	const DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
	                                           DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &owner,
	                                           nullptr, &dacl, nullptr, &descriptor);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot read ACL of " + from_wide(path), status);
	}
	SECURITY_DESCRIPTOR_CONTROL control = 0;
	DWORD revision = 0;
	GetSecurityDescriptorControl(descriptor, &control, &revision);
	return dacl_t{local_ptr{descriptor}, dacl, owner, control};
}

bool glaipnir::platform::windows::detail::has_exact_ace(PACL dacl, PSID sid, BYTE ace_type, DWORD mask, BYTE flags)
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
		if (header->AceType != ace_type || ace->Mask != mask ||
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

bool glaipnir::platform::windows::detail::groups_allow(PACL dacl, std::span<void* const> groups, DWORD mask)
{
	if (dacl == nullptr)
	{
		return false;
	}
	for (DWORD i = 0; i < dacl->AceCount; ++i)
	{
		void* raw = nullptr;
		if (!GetAce(dacl, i, &raw))
		{
			return false;
		}
		const auto* header = static_cast<ACE_HEADER*>(raw);
		if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || (header->AceFlags & INHERIT_ONLY_ACE) != 0)
		{
			continue;
		}
		const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
		for (void* group : groups)
		{
			if (EqualSid(const_cast<DWORD*>(&ace->SidStart), group) && (ace->Mask & mask) == mask)
			{
				return true;
			}
		}
	}
	return false;
}

bool glaipnir::platform::windows::detail::has_explicit_allow_for(PACL dacl, std::span<void* const> groups,
                                                                DWORD any_of_mask)
{
	if (dacl == nullptr)
	{
		return false;
	}
	for (DWORD i = 0; i < dacl->AceCount; ++i)
	{
		void* raw = nullptr;
		if (!GetAce(dacl, i, &raw))
		{
			return false;
		}
		const auto* header = static_cast<ACE_HEADER*>(raw);
		if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || (header->AceFlags & INHERITED_ACE) != 0)
		{
			continue;
		}
		const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
		if ((ace->Mask & any_of_mask) == 0)
		{
			continue;
		}
		for (void* group : groups)
		{
			if (EqualSid(const_cast<DWORD*>(&ace->SidStart), group))
			{
				return true;
			}
		}
	}
	return false;
}

bool glaipnir::platform::windows::detail::caller_owns(PSID owner)
{
	if (owner == nullptr)
	{
		return false;
	}
	BOOL member = FALSE;
	return CheckTokenMembership(nullptr, owner, &member) && member;
}


glaipnir::core::result_t<void> glaipnir::platform::windows::detail::write_dacl(const std::wstring& path, PACL dacl,
	SECURITY_DESCRIPTOR_CONTROL control, bool propagate)
{
	if (propagate)
	{
		const DWORD status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
		                                           DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
		if (status != ERROR_SUCCESS)
		{
			return win32_error("cannot write ACL of " + from_wide(path), status);
		}
		return core::ok();
	}
	SECURITY_DESCRIPTOR descriptor{};
	constexpr SECURITY_DESCRIPTOR_CONTROL kept_bits = SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED;
	if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
		!SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, FALSE) ||
		!SetSecurityDescriptorControl(&descriptor, kept_bits, control & kept_bits))
	{
		return last_error("cannot build security descriptor for " + from_wide(path));
	}
	if (!SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, &descriptor))
	{
		return last_error("cannot write ACL of " + from_wide(path));
	}
	return core::ok();
}

glaipnir::core::result_t<void> glaipnir::platform::windows::detail::apply_entry(const std::wstring& path,
	const dacl_t& current, PSID sid, ACCESS_MODE mode, DWORD mask, DWORD inheritance)
{
	EXPLICIT_ACCESS_W entry{};
	entry.grfAccessPermissions = mask;
	entry.grfAccessMode = mode;
	entry.grfInheritance = inheritance;
	entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	entry.Trustee.ptstrName = static_cast<LPWSTR>(sid);

	PACL new_dacl = nullptr;
	const DWORD status = SetEntriesInAclW(1, &entry, current.dacl, &new_dacl);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot build ACL for " + from_wide(path), status);
	}
	local_ptr new_dacl_owner{new_dacl};
	return write_dacl(path, new_dacl, current.control, inheritance != NO_INHERITANCE);
}

glaipnir::core::result_t<void> glaipnir::platform::windows::detail::remove_explicit_aces(const std::wstring& path,
	const dacl_t& current, PSID sid)
{
	std::vector<std::uint8_t> storage(current.dacl->AclSize);
	auto* new_dacl = reinterpret_cast<PACL>(storage.data());
	if (!InitializeAcl(new_dacl, static_cast<DWORD>(storage.size()), ACL_REVISION_DS))
	{
		return last_error("cannot build ACL for " + from_wide(path));
	}
	bool removed_inheritable = false;
	for (DWORD i = 0; i < current.dacl->AceCount; ++i)
	{
		void* raw = nullptr;
		if (!GetAce(current.dacl, i, &raw))
		{
			return last_error("cannot read ACL entry of " + from_wide(path));
		}
		const auto* header = static_cast<ACE_HEADER*>(raw);
		const bool ours = (header->AceFlags & INHERITED_ACE) == 0 &&
			(header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE) &&
			EqualSid(&static_cast<ACCESS_ALLOWED_ACE*>(raw)->SidStart, sid);
		if (ours)
		{
			removed_inheritable = removed_inheritable || (header->AceFlags & inherit_flags) != 0;
			continue;
		}
		if (!AddAce(new_dacl, ACL_REVISION_DS, MAXDWORD, raw, header->AceSize))
		{
			return last_error("cannot rebuild ACL of " + from_wide(path));
		}
	}
	return write_dacl(path, new_dacl, current.control, removed_inheritable);
}
