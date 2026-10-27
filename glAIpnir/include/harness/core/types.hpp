#pragma once
#include <nlohmann/json.hpp>
#include <atomic>
#include <filesystem>
#include <string>
#include <vector>

namespace harness {
using json_t = nlohmann::json;
struct limits_t {
    int operation_timeout_ms = 60000;
    std::size_t output_limit = 1024 * 1024;
    int http_timeout_ms = 120000;
    int max_turns = 32;
    int max_experiments = 32;
    std::size_t context_budget_bytes = 1024 * 1024;
    int context_recent_exchanges = 8;
};
enum class task_state_t { queued, running, succeeded, failed, cancelled, interrupted };
enum class target_kind_t { file, process, service, registry, machine };
struct research_target_t { target_kind_t kind = target_kind_t::file; json_t identity = json_t::object(); };
struct observation_t { std::string task_id; json_t data; };
struct hypothesis_t { std::string text; std::vector<std::string> observation_ids; };
struct experiment_t { std::string task_id; json_t parameters; };
struct artifact_t { std::string path; std::string sha256; std::uintmax_t size = 0; std::string record_id; };
struct finding_t { std::string text; bool verified = false; };
struct tool_call_t { std::string id; std::string name; json_t arguments; };
struct message_t {
    std::string role;
    std::string text;
    std::vector<tool_call_t> calls;
    std::string call_id;
    std::string tool_name;
    bool is_error = false;
    json_t native = nullptr;
};
struct model_reply_t { message_t message; std::string status; };
struct profile_t {
    std::string provider;
    std::string endpoint;
    std::string model;
    std::string key_env;
    int max_output_tokens = 4096;
};
std::wstring widen(const std::string& value);
std::string narrow(const std::wstring& value);
std::string path_text(const std::filesystem::path& path);
std::filesystem::path extended_path(const std::filesystem::path& path);
std::string timestamp();
std::string new_id();
std::string dump_json(const json_t& value, int indent = -1);
json_t read_json(const std::filesystem::path& path);
void write_text(const std::filesystem::path& path, const std::string& value);
std::string sha256(const std::filesystem::path& path, const std::atomic_bool* cancelled = nullptr);
json_t message_json(const message_t& message);
message_t parse_message(const json_t& value);
std::string state_text(task_state_t state);
limits_t parse_limits(const json_t& config);
void validate_arguments(const json_t& value, const json_t& rule, const std::string& path = "arguments");
profile_t parse_profile(const json_t& config, const std::string& name);
}
