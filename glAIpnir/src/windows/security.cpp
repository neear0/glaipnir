#include "harness/windows/analysis.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <cstring>

static harness::json_t decode_ace(const ACE_HEADER* header) {
    using harness::json_t;
    json_t result = {{"type", header->AceType}, {"flags", header->AceFlags}, {"size", header->AceSize},
        {"inherited", (header->AceFlags & INHERITED_ACE) != 0}, {"raw_hex", harness::windows::bytes_hex(header, header->AceSize)}};
    auto raw = reinterpret_cast<const unsigned char*>(header); std::size_t sid_offset = 0;
    if (header->AceSize >= 8) { DWORD mask{}; std::memcpy(&mask, raw + 4, sizeof(mask)); result["mask"] = mask; }
    switch (header->AceType) {
    case ACCESS_ALLOWED_ACE_TYPE: result["type_name"] = "allow"; sid_offset = 8; break;
    case ACCESS_DENIED_ACE_TYPE: result["type_name"] = "deny"; sid_offset = 8; break;
    case SYSTEM_AUDIT_ACE_TYPE: result["type_name"] = "audit"; sid_offset = 8; break;
    case SYSTEM_MANDATORY_LABEL_ACE_TYPE: result["type_name"] = "mandatory_label"; sid_offset = 8; break;
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case ACCESS_DENIED_OBJECT_ACE_TYPE:
        result["type_name"] = header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ? "allow_object" : "deny_object";
        if (header->AceSize >= 12) {
            DWORD flags{}; std::memcpy(&flags, raw + 8, sizeof(flags)); result["object_flags"] = flags;
            sid_offset = 12 + ((flags & ACE_OBJECT_TYPE_PRESENT) ? sizeof(GUID) : 0) + ((flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) ? sizeof(GUID) : 0);
        }
        break;
    default: result["type_name"] = "unsupported"; break;
    }
    if (sid_offset && sid_offset + 8 <= header->AceSize) {
        auto sid = const_cast<unsigned char*>(raw + sid_offset);
        const std::size_t sid_size = 8 + 4 * sid[1];
        if (sid_size <= header->AceSize - sid_offset && IsValidSid(sid)) result["sid"] = harness::windows::sid_text(sid);
        else result["malformed"] = true;
    }
    return result;
}
harness::json_t harness::windows::decode_descriptor(PSECURITY_DESCRIPTOR descriptor) {
    require_win(IsValidSecurityDescriptor(descriptor), "IsValidSecurityDescriptor");
    PSID owner{}, group{}; BOOL ignored{}; PACL dacl{}; BOOL present{}, defaulted{};
    require_win(GetSecurityDescriptorOwner(descriptor, &owner, &ignored), "GetSecurityDescriptorOwner");
    require_win(GetSecurityDescriptorGroup(descriptor, &group, &ignored), "GetSecurityDescriptorGroup");
    require_win(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted), "GetSecurityDescriptorDacl");
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
    require_win(GetSecurityDescriptorControl(descriptor, &control, &revision), "GetSecurityDescriptorControl");
    json_t result = {{"owner", owner ? json_t(sid_text(owner)) : json_t(nullptr)}, {"group", group ? json_t(sid_text(group)) : json_t(nullptr)},
        {"dacl_state", !present ? "absent" : !dacl ? "null" : dacl->AceCount == 0 ? "empty" : "present"},
        {"dacl_defaulted", defaulted != FALSE}, {"dacl_protected", (control & SE_DACL_PROTECTED) != 0}, {"control", control}, {"aces", json_t::array()}};
    if (dacl) {
        require_win(IsValidAcl(dacl), "IsValidAcl");
        for (DWORD index = 0; index < dacl->AceCount; ++index) {
            void* ace{}; require_win(GetAce(dacl, index, &ace), "GetAce"); result["aces"].push_back(decode_ace(static_cast<const ACE_HEADER*>(ace)));
        }
    }
    wchar_t* sddl{};
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sddl, nullptr)) {
        local_memory_t memory(sddl); result["sddl"] = narrow(sddl);
    } else result["errors"] = json_t::array({c_windows_error("ConvertSecurityDescriptorToStringSecurityDescriptor", GetLastError()).result()});
    return result;
}
harness::json_t harness::windows::check_descriptor_access(PSECURITY_DESCRIPTOR descriptor, HANDLE token, DWORD requested, GENERIC_MAPPING mapping) {
    require_win(IsValidSecurityDescriptor(descriptor), "IsValidSecurityDescriptor");
    PACL dacl{}; BOOL present{}, defaulted{};
    require_win(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted), "GetSecurityDescriptorDacl");
    if (dacl) for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* ace{}; require_win(GetAce(dacl, index, &ace), "GetAce"); const auto type = static_cast<ACE_HEADER*>(ace)->AceType;
        if (type != ACCESS_ALLOWED_ACE_TYPE && type != ACCESS_DENIED_ACE_TYPE)
            throw c_windows_error("Access check does not support conditional or object-specific ACEs", ERROR_NOT_SUPPORTED);
    }
    HANDLE duplicated{};
    require_win(DuplicateTokenEx(token, TOKEN_QUERY, nullptr, SecurityImpersonation, TokenImpersonation, &duplicated), "DuplicateTokenEx");
    c_handle impersonation(duplicated); DWORD mapped = requested; MapGenericMask(&mapped, &mapping);
    DWORD size = sizeof(PRIVILEGE_SET) + 16 * sizeof(LUID_AND_ATTRIBUTES), granted{}; BOOL allowed{};
    std::vector<unsigned char> privileges(size);
    if (!AccessCheck(descriptor, impersonation.get(), mapped, &mapping, reinterpret_cast<PRIVILEGE_SET*>(privileges.data()), &size, &granted, &allowed)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size > 1024 * 1024) require_win(FALSE, "AccessCheck");
        privileges.resize(size);
        require_win(AccessCheck(descriptor, impersonation.get(), mapped, &mapping, reinterpret_cast<PRIVILEGE_SET*>(privileges.data()), &size, &granted, &allowed), "AccessCheck");
    }
    return {{"ok", true}, {"access_allowed", allowed != FALSE}, {"requested_mask", requested}, {"mapped_mask", mapped}, {"granted_mask", granted},
        {"check_kind", "descriptor_token_discretionary"}, {"actual_open_guaranteed", false},
        {"generic_mapping", {{"read", mapping.GenericRead}, {"write", mapping.GenericWrite}, {"execute", mapping.GenericExecute}, {"all", mapping.GenericAll}}}};
}
static GENERIC_MAPPING generic_mapping(const std::string& kind) {
    if (kind == "file") return {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    if (kind == "registry") return {KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS};
    if (kind == "service") return {STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS,
        STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG, STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL, SERVICE_ALL_ACCESS};
    return {STANDARD_RIGHTS_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        STANDARD_RIGHTS_WRITE | PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME,
        STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, PROCESS_ALL_ACCESS};
}
harness::json_t harness::windows::security_analysis(const std::string& name, const harness::json_t& args, const std::filesystem::path& directory,
    const harness::limits_t& limits, const std::atomic_bool& cancelled) {
    if (cancelled.load()) return {{"ok", false}, {"cancelled", true}};
    const auto& target = args.at("target"); const std::string kind = target.at("kind");
    PSECURITY_DESCRIPTOR descriptor{};
    constexpr DWORD information = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    if (kind == "file") {
        auto path = std::filesystem::path(widen(target.at("path"))); if (path.is_relative()) path = directory / path;
        c_handle file(CreateFileW(path.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        require_win(file.valid(), "CreateFile READ_CONTROL"); require_status(GetSecurityInfo(file.get(), SE_FILE_OBJECT, information, nullptr, nullptr, nullptr, nullptr, &descriptor), "GetSecurityInfo file");
    } else if (kind == "process") {
        auto process = open_process(target, READ_CONTROL);
        require_status(GetSecurityInfo(process.get(), SE_KERNEL_OBJECT, information, nullptr, nullptr, nullptr, nullptr, &descriptor), "GetSecurityInfo process");
    } else if (kind == "service") {
        c_service_handle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)); require_win(manager.get() != nullptr, "OpenSCManager");
        c_service_handle service(OpenServiceW(manager.get(), widen(target.at("name")).c_str(), READ_CONTROL)); require_win(service.get() != nullptr, "OpenService READ_CONTROL");
        require_status(GetSecurityInfo(service.get(), SE_SERVICE, information, nullptr, nullptr, nullptr, nullptr, &descriptor), "GetSecurityInfo service");
    } else {
        HKEY hive{}, opened{}; std::wstring subkey; std::string canonical;
        parse_registry_path(target.at("key"), hive, subkey, canonical);
        require_status(RegOpenKeyExW(hive, subkey.c_str(), 0, READ_CONTROL | registry_view(target.value("view", "native")), &opened), "RegOpenKeyEx READ_CONTROL");
        c_registry_key key(opened);
        require_status(GetSecurityInfo(key.get(), SE_REGISTRY_KEY, information, nullptr, nullptr, nullptr, nullptr, &descriptor), "GetSecurityInfo registry");
    }
    local_memory_t memory(descriptor); auto result = decode_descriptor(descriptor); result["ok"] = true; result["target"] = target;
    if (name == "security_access_check") {
        json_t selected = json_t::object();
        if (args.contains("token_pid")) selected["pid"] = args.at("token_pid");
        if (args.contains("token_creation_time")) selected["creation_time"] = args.at("token_creation_time");
        json_t identity; auto token = open_token(selected, TOKEN_QUERY | TOKEN_DUPLICATE, &identity);
        auto check = check_descriptor_access(descriptor, token.get(), args.at("access_mask").get<DWORD>(), generic_mapping(kind));
        check["target"] = target; check["token_pid"] = args.value("token_pid", GetCurrentProcessId());
        check["token_creation_time"] = identity.at("creation_time");
        check["descriptor"] = std::move(result); result = std::move(check);
    }
    if (dump_json(result).size() > limits.output_limit) throw c_windows_error("Security information exceeds output_limit", ERROR_INSUFFICIENT_BUFFER);
    return result;
}
