#include "platform/windows/detail/mandatory_label.hpp"

#include <cstdint>
#include <vector>

#include "platform/windows/detail/c_sid.hpp"
#include "platform/windows/detail/dacl.hpp"

#include "glaipnir/core/path_util.hpp"

glaipnir::core::result_t<bool> glaipnir::platform::windows::detail::apply_low_label(const std::filesystem::path& path)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES)
	{
		return last_error("cannot access " + core::to_display_string(path), core::error_code::not_found);
	}
	const BYTE flags = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? inherit_flags : 0;

	auto low = c_sid::from_string("S-1-16-4096");
	if (!low)
	{
		return std::move(low).error();
	}

	PACL sacl = nullptr;
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr,
	                                     nullptr, &sacl, &descriptor);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot read integrity label of " + core::to_display_string(path), status);
	}
	local_ptr descriptor_owner{descriptor};
	if (sacl != nullptr)
	{
		for (DWORD i = 0; i < sacl->AceCount; ++i)
		{
			void* raw = nullptr;
			if (!GetAce(sacl, i, &raw))
			{
				break;
			}
			const auto* header = static_cast<ACE_HEADER*>(raw);
			if (header->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
			{
				continue;
			}
			const auto* ace = static_cast<SYSTEM_MANDATORY_LABEL_ACE*>(raw);
			if (EqualSid(const_cast<DWORD*>(&ace->SidStart), low->get()) &&
				(ace->Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) != 0 &&
				(header->AceFlags & (inherit_flags | INHERIT_ONLY_ACE)) == flags)
			{
				return false;
			}
		}
	}

	const DWORD size = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetLengthSid(low->get());
	std::vector<std::uint8_t> storage(size);
	auto* label = reinterpret_cast<PACL>(storage.data());
	if (!InitializeAcl(label, size, ACL_REVISION) ||
		!AddMandatoryAce(label, ACL_REVISION, flags, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, low->get()))
	{
		return last_error("cannot build integrity label");
	}
	status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
	                               nullptr, nullptr, nullptr, label);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot set integrity label of " + core::to_display_string(path), status);
	}
	return true;
}

glaipnir::core::result_t<void> glaipnir::platform::windows::detail::remove_label(const std::filesystem::path& path)
{
	if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
	{
		return core::ok();
	}
	ACL empty{};
	if (!InitializeAcl(&empty, sizeof(empty), ACL_REVISION))
	{
		return last_error("cannot build empty label");
	}
	const DWORD status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
	                                           LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &empty);
	if (status != ERROR_SUCCESS)
	{
		return win32_error("cannot clear integrity label of " + core::to_display_string(path), status);
	}
	return core::ok();
}
