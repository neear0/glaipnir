#include "harness/windows/analysis.hpp"
#include <sddl.h>
#include <array>

std::vector<unsigned char> harness::windows::token_data(HANDLE token, TOKEN_INFORMATION_CLASS type) {
    DWORD size{}; GetTokenInformation(token, type, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) require_win(FALSE, "GetTokenInformation size");
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (!size || size > 1024 * 1024) throw c_windows_error("Token information exceeds collection limit", ERROR_INSUFFICIENT_BUFFER);
        std::vector<unsigned char> bytes(size);
        if (GetTokenInformation(token, type, bytes.data(), static_cast<DWORD>(bytes.size()), &size)) { bytes.resize(size); return bytes; }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) require_win(FALSE, "GetTokenInformation");
    }
    throw c_windows_error("Token information changed repeatedly", ERROR_MORE_DATA);
}
std::string harness::windows::sid_text(PSID sid) {
    if (!sid || !IsValidSid(sid)) throw c_windows_error("Invalid SID", ERROR_INVALID_SID);
    wchar_t* text{}; require_win(ConvertSidToStringSidW(sid, &text), "ConvertSidToStringSid");
    local_memory_t memory(text); return narrow(text);
}
harness::c_handle harness::windows::open_token(const harness::json_t& args, DWORD rights, harness::json_t* identity) {
    c_handle process; HANDLE selected = GetCurrentProcess();
    if (args.contains("pid")) { process = open_process(args, PROCESS_QUERY_LIMITED_INFORMATION); selected = process.get(); }
    if (identity) *identity = {{"pid", args.value("pid", GetCurrentProcessId())}, {"creation_time", process_creation_time(selected)}};
    HANDLE token{}; require_win(OpenProcessToken(selected, rights, &token), "OpenProcessToken"); return c_handle(token);
}
static harness::json_t sid_attributes(const SID_AND_ATTRIBUTES& entry) {
    return {{"sid", harness::windows::sid_text(entry.Sid)}, {"attributes", entry.Attributes},
        {"enabled", (entry.Attributes & SE_GROUP_ENABLED) != 0}, {"deny_only", (entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0},
        {"mandatory", (entry.Attributes & SE_GROUP_MANDATORY) != 0}};
}
harness::json_t harness::windows::decode_token(HANDLE token) {
    json_t result = {{"ok", true}}; json_t errors = json_t::array();
    auto inspect = [&](const char* field, auto read) {
        try { result[field] = read(); } catch (const c_windows_error& error) { errors.push_back(error.result()); }
    };
    inspect("user", [&] { auto data = token_data(token, TokenUser); return sid_attributes(reinterpret_cast<TOKEN_USER*>(data.data())->User); });
    for (const auto& [field, type] : std::array<std::pair<const char*, TOKEN_INFORMATION_CLASS>, 3>{{{"groups", TokenGroups}, {"restricted_sids", TokenRestrictedSids}, {"capabilities", TokenCapabilities}}}) {
        inspect(field, [&] {
            auto data = token_data(token, type); const auto groups = reinterpret_cast<TOKEN_GROUPS*>(data.data()); json_t values = json_t::array();
            for (DWORD index = 0; index < groups->GroupCount; ++index) values.push_back(sid_attributes(groups->Groups[index]));
            return values;
        });
    }
    inspect("privileges", [&] {
        auto data = token_data(token, TokenPrivileges); auto privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(data.data()); json_t values = json_t::array();
        for (DWORD index = 0; index < privileges->PrivilegeCount; ++index) {
            const auto& privilege = privileges->Privileges[index]; std::array<wchar_t, 256> name{}; DWORD size = static_cast<DWORD>(name.size());
            json_t value = {{"luid_low", privilege.Luid.LowPart}, {"luid_high", privilege.Luid.HighPart}, {"attributes", privilege.Attributes},
                {"enabled", (privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0}, {"enabled_by_default", (privilege.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0}};
            if (LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&privilege.Luid), name.data(), &size)) value["name"] = narrow(std::wstring(name.data(), size));
            else value["errors"] = json_t::array({c_windows_error("LookupPrivilegeName", GetLastError()).result()});
            values.push_back(std::move(value));
        }
        return values;
    });
    inspect("integrity", [&] {
        auto data = token_data(token, TokenIntegrityLevel); auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(data.data())->Label.Sid;
        auto rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
        const char* level = rid < SECURITY_MANDATORY_LOW_RID ? "untrusted" : rid < SECURITY_MANDATORY_MEDIUM_RID ? "low" :
            rid < SECURITY_MANDATORY_HIGH_RID ? "medium" : rid < SECURITY_MANDATORY_SYSTEM_RID ? "high" : "system";
        return json_t{{"sid", sid_text(sid)}, {"rid", rid}, {"level", level}};
    });
    inspect("elevated", [&] { auto data = token_data(token, TokenElevation); return reinterpret_cast<TOKEN_ELEVATION*>(data.data())->TokenIsElevated != 0; });
    inspect("elevation_type", [&] { auto data = token_data(token, TokenElevationType); return static_cast<int>(*reinterpret_cast<TOKEN_ELEVATION_TYPE*>(data.data())); });
    inspect("token_type", [&] { auto data = token_data(token, TokenType); return *reinterpret_cast<TOKEN_TYPE*>(data.data()) == TokenPrimary ? "primary" : "impersonation"; });
    inspect("has_restrictions", [&] { auto data = token_data(token, TokenHasRestrictions); return *reinterpret_cast<DWORD*>(data.data()) != 0; });
    inspect("is_app_container", [&] { auto data = token_data(token, TokenIsAppContainer); return *reinterpret_cast<DWORD*>(data.data()) != 0; });
    if (!errors.empty()) { result["partial"] = true; result["errors"] = errors; }
    return result;
}
harness::json_t harness::windows::token_analysis(const harness::json_t& args, const harness::limits_t& limits, const std::atomic_bool& cancelled) {
    if (cancelled.load()) return {{"ok", false}, {"cancelled", true}};
    json_t identity; auto token = open_token(args, TOKEN_QUERY, &identity); auto result = decode_token(token.get());
    result.update(identity);
    if (dump_json(result).size() > limits.output_limit) throw c_windows_error("Token information exceeds output_limit", ERROR_INSUFFICIENT_BUFFER);
    return result;
}
harness::windows::c_privilege_scope::c_privilege_scope(bool enable_debug, HANDLE token, const wchar_t* privilege_name) {
    if (!enable_debug) return;
    if (!token) { owned_token_ = open_token(json_t::object(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES); token = owned_token_.get(); }
    token_ = token; TOKEN_PRIVILEGES requested{}; requested.PrivilegeCount = 1;
    require_win(LookupPrivilegeValueW(nullptr, privilege_name, &requested.Privileges[0].Luid), "LookupPrivilegeValue");
    requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; DWORD length = sizeof(previous_);
    SetLastError(ERROR_SUCCESS);
    require_win(AdjustTokenPrivileges(token_, FALSE, &requested, sizeof(previous_), &previous_, &length), "AdjustTokenPrivileges SeDebugPrivilege");
    const auto status = GetLastError();
    if (status != ERROR_SUCCESS) throw c_windows_error("Requested SeDebugPrivilege is unavailable", status);
    changed_ = previous_.PrivilegeCount != 0;
}
harness::windows::c_privilege_scope::~c_privilege_scope() { if (changed_) AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr); }
harness::json_t harness::windows::execution_context() {
    auto token = open_token(json_t::object(), TOKEN_QUERY); auto info = decode_token(token.get());
    bool debug = false;
    for (const auto& privilege : info.value("privileges", json_t::array())) if (privilege.value("name", "") == "SeDebugPrivilege") debug = privilege.at("enabled");
    return {{"user", info.value("user", json_t(nullptr))}, {"integrity", info.value("integrity", json_t(nullptr))},
        {"elevated", info.value("elevated", json_t(nullptr))}, {"debug_enabled", debug}};
}
