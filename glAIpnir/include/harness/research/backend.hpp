#pragma once
#include "harness/windows/analysis.hpp"
#include <chrono>
#include <functional>
#include <map>
#include <set>

namespace harness::research {
class c_context {
public:
    std::filesystem::path workspace;
    std::filesystem::path directory;
    limits_t limits;
    std::uintmax_t artifact_limit = 64 * 1024 * 1024;
    std::function<bool()> cancelled;
    std::filesystem::path path(const std::filesystem::path& relative) const;
    std::uintmax_t remaining() const;
    void save(const std::filesystem::path& relative, const std::string& bytes) const;
};
struct module_t { std::uint64_t base = 0; DWORD size = 0; std::string path; };
struct breakpoint_t { std::uint64_t address = 0; unsigned char original = 0; };
struct seed_t { std::string name; std::string bytes; std::string hash; };
struct thread_context_t {
    CONTEXT native{};
    WOW64_CONTEXT wow64{};
    bool is_wow64 = false;
    std::uint64_t pc() const;
    std::uint64_t sp() const;
    void set_pc(std::uint64_t address);
    void set_step(bool enabled);
};
struct dump_callback_t {
    HANDLE file = nullptr;
    std::uintmax_t limit = 0;
    const std::function<bool()>* cancelled = nullptr;
    bool budget_exhausted = false;
};
class c_debugger {
public:
    explicit c_debugger(c_context& context);
    ~c_debugger();
    json_t run(const json_t& args, const std::filesystem::path& relative, bool attach = false,
        const std::set<std::string>& known_signatures = {});
private:
    thread_context_t get_context(DWORD tid) const;
    void set_context(DWORD tid, thread_context_t& context) const;
    json_t snapshot(DWORD tid, const json_t& args);
    json_t locate(std::uint64_t address) const;
    void arm(std::uint64_t address);
    void restore_breakpoints() noexcept;
    void resume_threads() noexcept;
    void cleanup() noexcept;
    c_context& context_;
    c_handle process_;
    c_handle job_;
    DWORD pid_ = 0;
    bool attached_ = false;
    bool debugging_ = false;
    bool wow64_ = false;
    bool pending_ = false;
    bool symbols_ = false;
    DEBUG_EVENT event_{};
    DWORD pending_status_ = DBG_CONTINUE;
    std::map<DWORD, c_handle> threads_;
    std::map<std::uint64_t, module_t> modules_;
    std::map<std::uint64_t, breakpoint_t> breakpoints_;
    std::set<DWORD> suspended_;
};
json_t tool_definitions();
bool is_research_tool(const std::string& name);
json_t execute(const std::string& name, const json_t& args, const std::filesystem::path& directory,
    const limits_t& limits, const std::atomic_bool& cancelled, const std::filesystem::path& workspace);
json_t worker_execute(const std::string& name, const json_t& args, c_context& context);
json_t summarize_result(json_t result, const c_context& context);
json_t fuzz(const json_t& args, c_context& context);
json_t replay(const json_t& args, c_context& context);
json_t dump_process(const json_t& args, c_context& context);
json_t inspect_dump(const std::filesystem::path& path);
json_t write_dump(HANDLE process, DWORD pid, const std::filesystem::path& path, std::uintmax_t limit,
    const std::function<bool()>& cancelled, DWORD tid = 0, EXCEPTION_RECORD* exception = nullptr, thread_context_t* registers = nullptr);
std::string read_binary(const std::filesystem::path& path, std::size_t limit);
std::string data_hash(const std::string& data);
std::string hex_address(std::uint64_t value);
std::filesystem::path resolve_path(const std::string& value, const std::filesystem::path& directory);
std::string replace_input(std::string argument, const std::string& input);
}
