#include "harness/windows/analysis.hpp"
#include <algorithm>
#include <array>
#include <limits>

harness::windows::c_windows_error::c_windows_error(std::string operation, DWORD code)
    : std::runtime_error(operation + " failed (Windows error " + std::to_string(code) + ")"), operation_(std::move(operation)), code_(code) {}
harness::json_t harness::windows::c_windows_error::result() const {
    wchar_t* text{};
    const DWORD size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code_, 0, reinterpret_cast<wchar_t*>(&text), 0, nullptr);
    local_memory_t memory(text);
    return {{"ok", false}, {"operation", operation_}, {"error_code", code_},
        {"error", size ? narrow(std::wstring(text, size)) : what()}};
}
void harness::windows::require_win(BOOL result, const char* operation) { if (!result) throw c_windows_error(operation, GetLastError()); }
void harness::windows::require_status(LONG status, const char* operation) { if (status != ERROR_SUCCESS) throw c_windows_error(operation, static_cast<DWORD>(status)); }
std::string harness::windows::bytes_hex(const void* bytes, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    auto input = static_cast<const unsigned char*>(bytes); std::string result; result.reserve(size * 2);
    for (std::size_t index = 0; index < size; ++index) { result += digits[input[index] >> 4]; result += digits[input[index] & 15]; }
    return result;
}
harness::windows::c_page::c_page(const harness::json_t& args, const harness::limits_t& limits)
    : offset_(args.value("offset", std::size_t{0})), limit_(args.value("limit", std::size_t{256})), budget_(limits.output_limit) {}
bool harness::windows::c_page::add(harness::json_t item, std::size_t index) {
    if (index < offset_) return true;
    auto size = dump_json(item).size() + 1;
    if (items_.size() >= limit_ || size > budget_ || used_ > budget_ - size) {
        if (items_.empty() && items_.size() < limit_) throw c_windows_error("Enumeration item exceeds output_limit; increase the limit", ERROR_INSUFFICIENT_BUFFER);
        next_ = index; return false;
    }
    used_ += size; items_.push_back(std::move(item)); return true;
}
harness::json_t harness::windows::c_page::finish(bool cancelled) const {
    bool partial = false;
    for (const auto& item : items_) if (item.contains("errors")) partial = true;
    return {{"ok", !cancelled}, {"items", items_}, {"offset", offset_}, {"next_offset", next_},
        {"truncated", !next_.is_null()}, {"partial", partial || cancelled}, {"cancelled", cancelled}, {"snapshot", "live"}};
}
static harness::json_t object_schema(harness::json_t properties, harness::json_t required) {
    return {{"type", "object"}, {"properties", properties}, {"required", required}, {"additionalProperties", false}};
}
harness::json_t harness::windows::analysis_definitions() {
    const json_t text = {{"type", "string"}}, number = {{"type", "integer"}, {"minimum", 0}, {"maximum", 0xffffffffULL}};
    const json_t pid = {{"type", "integer"}, {"minimum", 1}, {"maximum", 0xffffffffULL}};
    const json_t view = {{"type", "string"}, {"enum", {"native", "32", "64"}}};
    const json_t page = {{"offset", number}, {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4096}}}};
    json_t process = {{"pid", pid}, {"creation_time", text}};
    json_t registry = {{"key", text}, {"view", view}};
    json_t result = json_t::array();
    auto add = [&](const char* name, const char* description, json_t properties, json_t required) {
        result.push_back({{"name", name}, {"description", description}, {"parameters", object_schema(std::move(properties), std::move(required))}});
    };
    add("process_list", "Enumerate local process identities and metadata. Results are a changing live snapshot.", page, json_t::array());
    add("process_info", "Inspect one process. Supply creation_time to prevent PID reuse.", process, {"pid"});
    auto process_page = process; process_page.update(page);
    add("process_modules", "Enumerate loaded modules of a process, including WOW64 modules.", process_page, {"pid"});
    add("process_threads", "Enumerate thread IDs and priorities in a process.", process_page, {"pid"});
    add("service_list", "Enumerate local Win32 services and drivers without changing their state.", page, json_t::array());
    add("service_info", "Read service configuration, status, account, dependencies, and description.", {{"name", text}}, {"name"});
    auto registry_page = registry; registry_page.update(page);
    add("registry_list", "Enumerate immediate subkeys and value metadata at a local registry key.", registry_page, {"key"});
    auto registry_read = registry; registry_read["name"] = text;
    add("registry_read", "Read a registry value. Empty name selects the default value. Expandable strings are not expanded.", registry_read, {"key", "name"});
    add("token_info", "Inspect the current process token or a selected process token, including SID, groups, privileges, and restrictions.", process, json_t::array());
    json_t selector = object_schema({{"kind", {{"type", "string"}, {"enum", {"file", "process", "service", "registry"}}}},
        {"path", text}, {"pid", pid}, {"creation_time", text}, {"name", text}, {"key", text}, {"view", view}}, {"kind"});
    add("security_descriptor", "Read owner, group and DACL of a file/directory, process, service, or registry key. No SACL auditing inspection.", {{"target", selector}}, {"target"});
    add("security_access_check", "Evaluate descriptor/token discretionary access. This is not a guarantee that opening the object will succeed.",
        {{"target", selector}, {"access_mask", number}, {"token_pid", pid}, {"token_creation_time", text}}, {"target", "access_mask"});
    return result;
}
harness::json_t harness::windows::execute_analysis(const std::string& name, const harness::json_t& args, const std::filesystem::path& directory,
    const harness::limits_t& limits, const std::atomic_bool& cancelled) {
    if (name.starts_with("process_")) return process_analysis(name, args, limits, cancelled);
    if (name.starts_with("service_")) return service_analysis(name, args, limits, cancelled);
    if (name.starts_with("registry_")) return registry_analysis(name, args, limits, cancelled);
    if (name == "token_info") return token_analysis(args, limits, cancelled);
    return security_analysis(name, args, directory, limits, cancelled);
}
harness::research_target_t harness::windows::resolve_target(harness::target_kind_t kind, const std::string& locator, const std::string& view) {
    research_target_t target{kind, json_t::object()};
    if (kind == target_kind_t::file) {
        auto path = std::filesystem::canonical(widen(locator));
        if (!std::filesystem::is_regular_file(path)) throw std::runtime_error("File session target must be a regular file");
        target.identity = {{"kind", "file"}, {"path", path_text(path)}, {"sha256", sha256(path)}};
    } else if (kind == target_kind_t::process) {
        if (locator.empty() || locator.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("PID must be a positive integer");
        auto value = std::stoull(locator);
        if (!value || value > MAXDWORD) throw std::runtime_error("PID is outside its valid range");
        auto process = open_process({{"pid", value}}, PROCESS_QUERY_LIMITED_INFORMATION);
        target.identity = {{"kind", "process"}, {"pid", value}, {"creation_time", process_creation_time(process.get())}};
    } else if (kind == target_kind_t::service) {
        c_service_handle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)); require_win(manager.get() != nullptr, "OpenSCManager");
        c_service_handle service(OpenServiceW(manager.get(), widen(locator).c_str(), SERVICE_QUERY_STATUS)); require_win(service.get() != nullptr, "OpenService");
        target.identity = {{"kind", "service"}, {"name", locator}};
    } else if (kind == target_kind_t::registry) {
        HKEY hive{}; std::wstring subkey; std::string canonical;
        parse_registry_path(locator, hive, subkey, canonical); HKEY key{};
        require_status(RegOpenKeyExW(hive, subkey.c_str(), 0, KEY_QUERY_VALUE | registry_view(view), &key), "RegOpenKeyEx");
        c_registry_key handle(key);
        target.identity = {{"kind", "registry"}, {"key", canonical + (subkey.empty() ? "" : "\\" + narrow(subkey))}, {"view", view == "native" ? "64" : view}};
    } else target.identity = {{"kind", "machine"}};
    return target;
}
harness::json_t harness::windows::target_json(const harness::research_target_t& target) { return target.identity; }
harness::json_t harness::windows::normalize_session(harness::json_t session) {
    if (!session.contains("target_info")) session["target_info"] = {{"kind", "file"}, {"path", session.at("target")}, {"sha256", session.at("target_sha256")}};
    return session;
}
