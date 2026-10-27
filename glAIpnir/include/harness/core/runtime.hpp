#pragma once
#include "harness/storage/store.hpp"
#include "harness/ai/model.hpp"
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <thread>

namespace harness {
class c_task_scheduler {
public:
    c_task_scheduler();
    ~c_task_scheduler();
    std::future<json_t> schedule(std::function<json_t()> operation);
private:
    std::mutex mutex_;
    std::condition_variable_any ready_;
    std::deque<std::packaged_task<json_t()>> queue_;
    std::jthread worker_;
};
class c_runtime {
public:
    c_runtime(storage::c_evidence_store& store, json_t config, std::atomic_bool& cancelled, bool debug_requested = false);
    json_t dispatch(const std::string& session_id, const std::string& tool, const json_t& arguments, const std::string& call_id = "", const std::string& run_id = "");
    json_t investigate(const std::string& session_id, const std::string& goal, const std::string& profile,
        std::shared_ptr<ai::c_http_transport> transport = std::make_shared<ai::c_winhttp_transport>());
    std::string create_session(const std::filesystem::path& target);
    std::string create_session(const research_target_t& target);
    json_t research_context(const std::string& session_id);
private:
    json_t dispatch_native(const std::string& session_id, const std::string& tool, const json_t& arguments, const std::string& call_id, const json_t& experiment = nullptr);
    storage::c_evidence_store& store_;
    json_t config_;
    limits_t limits_;
    std::atomic_bool& cancelled_;
    c_task_scheduler scheduler_;
};
json_t public_config(const json_t& config);
}
