#pragma once
#include "harness/core/util.hpp"
#include <winsvc.h>
#include <memory>

namespace harness::windows {
class c_windows_error : public std::runtime_error {
public:
    c_windows_error(std::string operation, DWORD code);
    json_t result() const;
private:
    std::string operation_;
    DWORD code_;
};
void require_win(BOOL result, const char* operation);
void require_status(LONG status, const char* operation);
class c_service_handle {
public:
    explicit c_service_handle(SC_HANDLE handle = nullptr) : handle_(handle) {}
    ~c_service_handle() { if (handle_) CloseServiceHandle(handle_); }
    c_service_handle(const c_service_handle&) = delete;
    c_service_handle& operator=(const c_service_handle&) = delete;
    SC_HANDLE get() const noexcept { return handle_; }
private:
    SC_HANDLE handle_;
};
class c_registry_key {
public:
    explicit c_registry_key(HKEY key = nullptr) : key_(key) {}
    ~c_registry_key() { if (key_) RegCloseKey(key_); }
    c_registry_key(const c_registry_key&) = delete;
    c_registry_key& operator=(const c_registry_key&) = delete;
    HKEY get() const noexcept { return key_; }
private:
    HKEY key_;
};
struct local_free_t { void operator()(void* memory) const noexcept { if (memory) LocalFree(memory); } };
using local_memory_t = std::unique_ptr<void, local_free_t>;
class c_page {
public:
    c_page(const json_t& args, const limits_t& limits);
    bool add(json_t item, std::size_t index);
    json_t finish(bool cancelled = false) const;
private:
    std::size_t offset_, limit_, budget_, used_ = 256;
    json_t items_ = json_t::array();
    json_t next_ = nullptr;
};
json_t analysis_definitions();
json_t execute_analysis(const std::string& name, const json_t& args, const std::filesystem::path& directory,
    const limits_t& limits, const std::atomic_bool& cancelled);
json_t process_analysis(const std::string& name, const json_t& args, const limits_t& limits, const std::atomic_bool& cancelled);
json_t service_analysis(const std::string& name, const json_t& args, const limits_t& limits, const std::atomic_bool& cancelled);
json_t registry_analysis(const std::string& name, const json_t& args, const limits_t& limits, const std::atomic_bool& cancelled);
json_t token_analysis(const json_t& args, const limits_t& limits, const std::atomic_bool& cancelled);
json_t security_analysis(const std::string& name, const json_t& args, const std::filesystem::path& directory,
    const limits_t& limits, const std::atomic_bool& cancelled);
c_handle open_process(const json_t& args, DWORD rights);
std::string process_creation_time(HANDLE process);
c_handle open_token(const json_t& args, DWORD rights, json_t* identity = nullptr);
json_t decode_token(HANDLE token);
json_t decode_descriptor(PSECURITY_DESCRIPTOR descriptor);
json_t check_descriptor_access(PSECURITY_DESCRIPTOR descriptor, HANDLE token, DWORD requested, GENERIC_MAPPING mapping);
json_t decode_registry_value(DWORD type, const std::vector<unsigned char>& bytes);
json_t decode_service_config(const QUERY_SERVICE_CONFIGW& config);
std::string sid_text(PSID sid);
std::string bytes_hex(const void* bytes, std::size_t size);
std::vector<unsigned char> token_data(HANDLE token, TOKEN_INFORMATION_CLASS type);
void parse_registry_path(const std::string& path, HKEY& hive, std::wstring& subkey, std::string& canonical_hive);
REGSAM registry_view(const std::string& view);
research_target_t resolve_target(target_kind_t kind, const std::string& locator, const std::string& view = "native");
json_t target_json(const research_target_t& target);
json_t normalize_session(json_t session);
json_t execution_context();
class c_privilege_scope {
public:
    explicit c_privilege_scope(bool enable_debug, HANDLE token = nullptr, const wchar_t* privilege_name = SE_DEBUG_NAME);
    ~c_privilege_scope();
    c_privilege_scope(const c_privilege_scope&) = delete;
    c_privilege_scope& operator=(const c_privilege_scope&) = delete;
private:
    c_handle owned_token_;
    HANDLE token_ = nullptr;
    TOKEN_PRIVILEGES previous_{};
    bool changed_ = false;
};
}
