#pragma once

#include <memory>
#include <span>
#include <string>

#include "platform/windows/detail/win_util.hpp"

#include <aclapi.h>

namespace glaipnir::platform::windows::detail
{
	inline constexpr DWORD read_mask = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
	inline constexpr DWORD write_mask = read_mask | FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
	inline constexpr DWORD traverse_mask = FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;
	inline constexpr DWORD deny_mask = FILE_ALL_ACCESS & ~static_cast<DWORD>(FILE_READ_ATTRIBUTES | SYNCHRONIZE);
	inline constexpr DWORD exposure_read_bits = FILE_READ_DATA | GENERIC_READ | GENERIC_ALL;
	inline constexpr BYTE inherit_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

	struct local_free_t
	{
		void operator()(void* memory) const noexcept { LocalFree(memory); }
	};

	using local_ptr = std::unique_ptr<void, local_free_t>;

	struct dacl_t
	{
		local_ptr descriptor;
		PACL dacl = nullptr;
		PSID owner = nullptr;
		SECURITY_DESCRIPTOR_CONTROL control = 0;
	};

	core::result_t<dacl_t> read_dacl(const std::wstring& path);

	bool has_exact_ace(PACL dacl, PSID sid, BYTE ace_type, DWORD mask, BYTE flags);

	bool has_any_explicit_ace(PACL dacl, PSID sid);

	bool groups_allow(PACL dacl, std::span<void* const> groups, DWORD mask);

	bool has_explicit_allow_for(PACL dacl, std::span<void* const> groups, DWORD any_of_mask);

	bool caller_owns(PSID owner);

	core::result_t<void> write_dacl(const std::wstring& path, PACL dacl, SECURITY_DESCRIPTOR_CONTROL control,
	                                bool propagate);

	core::result_t<void> apply_entry(const std::wstring& path, const dacl_t& current, PSID sid, ACCESS_MODE mode,
	                                 DWORD mask, DWORD inheritance);

	core::result_t<void> remove_explicit_aces(const std::wstring& path, const dacl_t& current, PSID sid);
}
