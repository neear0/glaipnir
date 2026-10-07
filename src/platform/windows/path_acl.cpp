#include "glaipnir/platform/windows/path_acl.hpp"

#include "platform/windows/detail/dacl.hpp"

#include "glaipnir/core/path_util.hpp"

glaipnir::core::result_t<glaipnir::platform::windows::grant_outcome>
glaipnir::platform::windows::grant_path_access(const std::filesystem::path& path, void* sid, grant_kind kind,
                                               std::span<void* const> baseline_groups)
{
	if (path == path.root_path() || !path.has_relative_path())
	{
		return grant_outcome::skipped;
	}
	const std::wstring wide_path = path.native();
	const DWORD attributes = GetFileAttributesW(wide_path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES)
	{
		return detail::last_error("cannot access " + core::to_display_string(path), core::error_code::not_found);
	}
	const bool is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
	const bool inheritable = is_directory && kind != grant_kind::traverse;

	BYTE ace_type = ACCESS_ALLOWED_ACE_TYPE;
	ACCESS_MODE mode = SET_ACCESS;
	DWORD mask = detail::read_mask;
	switch (kind)
	{
	case grant_kind::read_only: mask = detail::read_mask;
		break;
	case grant_kind::read_write: mask = detail::write_mask;
		break;
	case grant_kind::traverse: mask = detail::traverse_mask;
		break;
	case grant_kind::deny: mask = detail::deny_mask;
		ace_type = ACCESS_DENIED_ACE_TYPE;
		mode = DENY_ACCESS;
		break;
	}
	const BYTE flags = inheritable ? detail::inherit_flags : 0;

	auto current = detail::read_dacl(wide_path);
	if (!current)
	{
		return std::move(current).error();
	}
	if (current->dacl == nullptr)
	{
		if (kind == grant_kind::traverse)
		{
			return grant_outcome::skipped;
		}
		return core::make_error(core::error_code::permission_denied,
		                        core::to_display_string(path) + " has no DACL; refusing to modify it");
	}
	if (detail::has_exact_ace(current->dacl, sid, ace_type, mask, flags))
	{
		return grant_outcome::unchanged;
	}
	if ((kind == grant_kind::read_only || kind == grant_kind::traverse) &&
		!detail::has_any_explicit_ace(current->dacl, sid) &&
		detail::groups_allow(current->dacl, baseline_groups, mask))
	{
		return grant_outcome::already_allowed;
	}
	if (kind == grant_kind::traverse && !detail::caller_owns(current->owner))
	{
		return grant_outcome::skipped;
	}

	if (detail::has_any_explicit_ace(current->dacl, sid))
	{
		auto removed = detail::remove_explicit_aces(wide_path, *current, sid);
		if (!removed)
		{
			return std::move(removed).error();
		}
		current = detail::read_dacl(wide_path);
		if (!current)
		{
			return std::move(current).error();
		}
	}
	auto applied = detail::apply_entry(wide_path, *current, sid, mode, mask,
	                                   inheritable ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE);
	if (!applied)
	{
		if (kind == grant_kind::traverse)
		{
			return grant_outcome::skipped;
		}
		return std::move(applied).error();
	}
	return grant_outcome::granted;
}

glaipnir::core::result_t<void> glaipnir::platform::windows::revoke_path_access(
	const std::filesystem::path& path, void* sid)
{
	const std::wstring wide_path = path.native();
	if (GetFileAttributesW(wide_path.c_str()) == INVALID_FILE_ATTRIBUTES)
	{
		return core::ok();
	}
	auto current = detail::read_dacl(wide_path);
	if (!current)
	{
		return std::move(current).error();
	}
	if (current->dacl == nullptr || !detail::has_any_explicit_ace(current->dacl, sid))
	{
		return core::ok();
	}
	return detail::remove_explicit_aces(wide_path, *current, sid);
}

glaipnir::core::result_t<bool> glaipnir::platform::windows::is_exposed_to(const std::filesystem::path& path,
                                                                         std::span<void* const> groups)
{
	auto current = detail::read_dacl(path.native());
	if (!current)
	{
		return std::move(current).error();
	}
	return detail::has_explicit_allow_for(current->dacl, groups, detail::exposure_read_bits);
}
