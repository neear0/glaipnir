#include "glaipnir/platform/windows/path_acl.hpp"

#include "win_util.hpp"

#include <aclapi.h>
#include <sddl.h>

#include "glaipnir/core/path_util.hpp"

namespace glaipnir::platform::windows {

using core::error_code;
using core::result_t;

namespace {

constexpr DWORD read_mask = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
// Deliberately excludes WRITE_DAC and WRITE_OWNER.
constexpr DWORD write_mask = read_mask | FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
constexpr BYTE inherit_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

struct local_free_t {
    void operator()(void* memory) const noexcept { LocalFree(memory); }
};
using local_ptr = std::unique_ptr<void, local_free_t>;

struct dacl_t {
    local_ptr descriptor; // owns the memory `dacl` points into
    PACL dacl = nullptr;
};

result_t<dacl_t> read_dacl(const std::wstring& path) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                               &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS) {
        return win32_error("cannot read ACL of " + from_wide(path), status);
    }
    return dacl_t{local_ptr{descriptor}, dacl};
}

// True when the only explicit ACEs for `sid` are a single allow ACE with exactly this mask and
// inheritance, i.e. rewriting the DACL (and re-propagating through a large tree) is pointless.
bool has_exact_grant(PACL dacl, PSID sid, DWORD mask, BYTE flags) {
    int matching = 0;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) {
            return false;
        }
        const auto* header = static_cast<ACE_HEADER*>(raw);
        if ((header->AceFlags & INHERITED_ACE) != 0) {
            continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) {
            continue;
        }
        // Allowed and denied ACEs share the layout up to SidStart.
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if (!EqualSid(&ace->SidStart, sid)) {
            continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Mask != mask ||
            (header->AceFlags & (inherit_flags | INHERIT_ONLY_ACE)) != flags) {
            return false;
        }
        ++matching;
    }
    return matching == 1;
}

bool has_any_explicit_ace(PACL dacl, PSID sid) {
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) {
            return true; // be conservative: let the revoke run
        }
        const auto* header = static_cast<ACE_HEADER*>(raw);
        if ((header->AceFlags & INHERITED_ACE) == 0 &&
            (header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE) &&
            EqualSid(&static_cast<ACCESS_ALLOWED_ACE*>(raw)->SidStart, sid)) {
            return true;
        }
    }
    return false;
}

// Locations like Program Files are not ours to re-ACL, but they already grant read to every
// AppContainer through a package-wide group. Under LPAC only the restricted group counts.
bool package_group_allows(PACL dacl, DWORD mask, bool less_privileged) {
    PSID group = nullptr;
    if (!ConvertStringSidToSidW(less_privileged ? L"S-1-15-2-2" : L"S-1-15-2-1", &group)) {
        return false;
    }
    local_ptr group_owner{group};
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) {
            return false;
        }
        const auto* header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE && (header->AceFlags & INHERIT_ONLY_ACE) == 0) {
            const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
            if (EqualSid(const_cast<DWORD*>(&ace->SidStart), group) && (ace->Mask & mask) == mask) {
                return true;
            }
        }
    }
    return false;
}

result_t<void> apply_entry(const std::wstring& path, PACL old_dacl, PSID sid, ACCESS_MODE mode, DWORD mask, DWORD inheritance) {
    EXPLICIT_ACCESS_W entry{};
    entry.grfAccessPermissions = mask;
    entry.grfAccessMode = mode;
    entry.grfInheritance = inheritance;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    entry.Trustee.ptstrName = static_cast<LPWSTR>(sid);

    PACL new_dacl = nullptr;
    DWORD status = SetEntriesInAclW(1, &entry, old_dacl, &new_dacl);
    if (status != ERROR_SUCCESS) {
        return win32_error("cannot build ACL for " + from_wide(path), status);
    }
    local_ptr new_dacl_owner{new_dacl};
    status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                   nullptr, new_dacl, nullptr);
    if (status != ERROR_SUCCESS) {
        return win32_error("cannot write ACL of " + from_wide(path), status);
    }
    return core::ok();
}

} // namespace

result_t<grant_outcome> grant_path_access(const std::filesystem::path& path, void* sid, policy::access_mode access,
                                          bool less_privileged) {
    const std::wstring wide_path = path.native();
    const DWORD attributes = GetFileAttributesW(wide_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return last_error("cannot access " + core::to_display_string(path), error_code::not_found);
    }
    const bool is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    const DWORD mask = access == policy::access_mode::read_write ? write_mask : read_mask;
    const BYTE flags = is_directory ? inherit_flags : 0;

    auto current = read_dacl(wide_path);
    if (!current) {
        return std::move(current).error();
    }
    if (current->dacl == nullptr) {
        // A NULL DACL means "everyone has full access"; merging into it would produce a DACL
        // containing only our ACE and lock the owner out. Refuse instead of guessing.
        return core::make_error(error_code::permission_denied,
                                core::to_display_string(path) + " has no DACL; refusing to modify it");
    }
    if (has_exact_grant(current->dacl, sid, mask, flags)) {
        return grant_outcome::unchanged;
    }
    auto applied = apply_entry(wide_path, current->dacl, sid, SET_ACCESS, mask,
                               is_directory ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE);
    if (!applied) {
        if (access == policy::access_mode::read_only && applied.error().native_code == ERROR_ACCESS_DENIED &&
            package_group_allows(current->dacl, mask, less_privileged)) {
            return grant_outcome::already_allowed;
        }
        return std::move(applied).error();
    }
    return grant_outcome::granted;
}

result_t<void> revoke_path_access(const std::filesystem::path& path, void* sid) {
    const std::wstring wide_path = path.native();
    if (GetFileAttributesW(wide_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return core::ok(); // nothing left to revoke from
    }
    auto current = read_dacl(wide_path);
    if (!current) {
        return std::move(current).error();
    }
    if (current->dacl == nullptr || !has_any_explicit_ace(current->dacl, sid)) {
        return core::ok();
    }
    return apply_entry(wide_path, current->dacl, sid, REVOKE_ACCESS, 0, NO_INHERITANCE);
}

} // namespace glaipnir::platform::windows
