#pragma once
#include "harness/core/runtime.hpp"
#include "harness/windows/analysis.hpp"
#include "harness/windows/tools.hpp"
#include <sddl.h>
#include <iostream>

namespace harness::tests {
inline void check(bool value, const std::string& message) { if (!value) throw std::runtime_error(message); }
template<class c_function> void fails(c_function function, const std::string& message) {
    bool failed = false; try { function(); } catch (const std::exception&) { failed = true; } check(failed, message);
}
class c_process_fixture {
public:
    explicit c_process_fixture(const std::filesystem::path& executable) {
        auto command = quote_argument(executable.wstring()) + L" sleep";
        STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
        windows::require_win(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process), "CreateProcess fixture");
        process_ = c_handle(process.hProcess); c_handle thread(process.hThread); pid_ = process.dwProcessId;
    }
    ~c_process_fixture() { TerminateProcess(process_.get(), 0); WaitForSingleObject(process_.get(), 2000); }
    DWORD pid() const { return pid_; }
    HANDLE handle() const { return process_.get(); }
private:
    c_handle process_;
    DWORD pid_{};
};
class c_registry_fixture {
public:
    c_registry_fixture() : key_(L"Software\\glAIpnirTests\\" + widen(new_id())) {
        HKEY handle{}; windows::require_status(RegCreateKeyExW(HKEY_CURRENT_USER, key_.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &handle, nullptr), "Create registry fixture");
        RegCloseKey(handle);
    }
    ~c_registry_fixture() { RegDeleteTreeW(HKEY_CURRENT_USER, key_.c_str()); }
    std::string path() const { return "HKCU\\" + narrow(key_); }
    void set(const wchar_t* name, DWORD type, const void* bytes, DWORD length) {
        HKEY handle{}; windows::require_status(RegOpenKeyExW(HKEY_CURRENT_USER, key_.c_str(), 0, KEY_SET_VALUE, &handle), "Open registry fixture");
        windows::c_registry_key key(handle); windows::require_status(RegSetValueExW(handle, name, 0, type, static_cast<const BYTE*>(bytes), length), "Set fixture value");
    }
private:
    std::wstring key_;
};
class c_script_model final : public ai::c_http_transport {
public:
    explicit c_script_model(std::vector<tool_call_t> calls) : calls_(std::move(calls)) {}
    json_t post(const std::string&, const ai::headers_t&, const json_t& body, int, const std::atomic_bool&) override {
        requests.push_back(body);
        if (requests.size() > 1) return {{"done", true}, {"message", {{"role", "assistant"}, {"content", "Native observations collected. No verified finding."}}}};
        json_t calls = json_t::array();
        for (const auto& call : calls_) calls.push_back({{"function", {{"name", call.name}, {"arguments", call.arguments}}}});
        return {{"done", true}, {"message", {{"role", "assistant"}, {"content", ""}, {"tool_calls", calls}}}};
    }
    std::vector<json_t> requests;
private:
    std::vector<tool_call_t> calls_;
};
}
