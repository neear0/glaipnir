#include "glaipnir/platform/windows/path_acl.hpp"

#include "platform/windows/detail/dacl.hpp"

#include "glaipnir/core/path_util.hpp"

glaipnir::core::result_t<glaipnir::platform::windows::grant_outcome>
glaipnir::platform::windows::grant_path_access(const std::filesystem::path& path, void* sid, policy::access_mode access,
                                               bool less_privileged) {
    const std::wstring wide_path = path.native();
    const DWORD attributes = GetFileAttributesW(wide_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return detail::last_error("cannot access " + core::to_display_string(path), core::error_code::not_found);
    }
    const bool is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    const DWORD mask = access == policy::access_mode::read_write ? detail::write_mask : detail::read_mask;
    const BYTE flags = is_directory ? detail::inherit_flags : 0;

    auto current = detail::read_dacl(wide_path);
    if (!current) {
        return std::move(current).error();
    }
    if (current->dacl == nullptr) {
        return core::make_error(core::error_code::permission_denied,
                                core::to_display_string(path) + " has no DACL; refusing to modify it");
    }
    if (detail::has_exact_grant(current->dacl, sid, mask, flags)) {
        return grant_outcome::unchanged;
    }
    auto applied = detail::apply_entry(wide_path, current->dacl, sid, SET_ACCESS, mask,
                                       is_directory ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE);
    if (!applied) {
        if (access == policy::access_mode::read_only && applied.error().native_code == ERROR_ACCESS_DENIED &&
            detail::package_group_allows(current->dacl, mask, less_privileged)) {
            return grant_outcome::already_allowed;
        }
        return std::move(applied).error();
    }
    return grant_outcome::granted;
}

glaipnir::core::result_t<void> glaipnir::platform::windows::revoke_path_access(const std::filesystem::path& path, void* sid) {
    const std::wstring wide_path = path.native();
    if (GetFileAttributesW(wide_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return core::ok();
    }
    auto current = detail::read_dacl(wide_path);
    if (!current) {
        return std::move(current).error();
    }
    if (current->dacl == nullptr || !detail::has_any_explicit_ace(current->dacl, sid)) {
        return core::ok();
    }
    return detail::apply_entry(wide_path, current->dacl, sid, REVOKE_ACCESS, 0, NO_INHERITANCE);
}
