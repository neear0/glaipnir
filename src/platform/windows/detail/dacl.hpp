#pragma once

#include <memory>
#include <string>

#include "platform/windows/detail/win_util.hpp"

#include <aclapi.h>

namespace glaipnir::platform::windows::detail {

inline constexpr DWORD read_mask = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
inline constexpr DWORD write_mask = read_mask | FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
inline constexpr BYTE inherit_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

struct local_free_t {
    void operator()(void* memory) const noexcept { LocalFree(memory); }
};
using local_ptr = std::unique_ptr<void, local_free_t>;

struct dacl_t {
    local_ptr descriptor;
    PACL dacl = nullptr;
};

core::result_t<dacl_t> read_dacl(const std::wstring& path);

bool has_exact_grant(PACL dacl, PSID sid, DWORD mask, BYTE flags);

bool has_any_explicit_ace(PACL dacl, PSID sid);

bool package_group_allows(PACL dacl, DWORD mask, bool less_privileged);

core::result_t<void> apply_entry(const std::wstring& path, PACL old_dacl, PSID sid, ACCESS_MODE mode, DWORD mask,
                                 DWORD inheritance);

}
