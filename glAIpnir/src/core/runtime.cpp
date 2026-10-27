#include "harness/core/runtime.hpp"
#include "harness/windows/tools.hpp"
#include "harness/windows/analysis.hpp"
#include "harness/research/backend.hpp"
#include "harness/research/session.hpp"
#include "harness/ai/orchestrator.hpp"
#include <chrono>

harness::c_task_scheduler::c_task_scheduler() : worker_([this](std::stop_token stop) {
    for (;;) {
        std::packaged_task<json_t()> operation;
        {
            std::unique_lock lock(mutex_);
            ready_.wait(lock, stop, [this] { return !queue_.empty(); });
            if (queue_.empty() && stop.stop_requested()) return;
            operation = std::move(queue_.front()); queue_.pop_front();
        }
        operation();
    }
}) {}
harness::c_task_scheduler::~c_task_scheduler() { worker_.request_stop(); ready_.notify_all(); }
std::future<harness::json_t> harness::c_task_scheduler::schedule(std::function<harness::json_t()> operation) {
    std::packaged_task<json_t()> task(std::move(operation)); auto future = task.get_future();
    { std::lock_guard lock(mutex_); queue_.push_back(std::move(task)); }
    ready_.notify_one(); return future;
}
harness::json_t harness::public_config(const harness::json_t& config) {
    auto limits = parse_limits(config);
    json_t result = {{"limits", {{"operation_timeout_ms", limits.operation_timeout_ms}, {"output_limit", limits.output_limit},
        {"http_timeout_ms", limits.http_timeout_ms}, {"max_turns", limits.max_turns}, {"max_experiments", limits.max_experiments},
        {"context_budget_bytes", limits.context_budget_bytes}, {"context_recent_exchanges", limits.context_recent_exchanges}}}, {"profiles", json_t::object()}};
    const auto profiles = config.value("profiles", json_t::object());
    for (const auto& [name, ignored] : profiles.items()) {
        (void)ignored;
        auto profile = parse_profile(config, name);
        if (profile.endpoint.find_first_of("@?#\r\n") != std::string::npos) throw std::runtime_error("Endpoint must not contain credentials, query, or fragment");
        result["profiles"][name] = {{"provider", profile.provider}, {"endpoint", profile.endpoint}, {"model", profile.model},
            {"key_env", profile.key_env}, {"max_output_tokens", profile.max_output_tokens}};
    }
    return result;
}
harness::c_runtime::c_runtime(harness::storage::c_evidence_store& store, harness::json_t config, std::atomic_bool& cancelled, bool debug_requested)
    : store_(store), config_(public_config(config)), limits_(parse_limits(config_)), cancelled_(cancelled) {
    config_["execution_context"] = windows::execution_context(); config_["execution_context"]["debug_requested"] = debug_requested;
}
std::string harness::c_runtime::create_session(const std::filesystem::path& target) { return store_.create_session(target, config_); }
std::string harness::c_runtime::create_session(const harness::research_target_t& target) { return store_.create_session(target, config_); }
harness::json_t harness::c_runtime::research_context(const std::string& session_id) {
    auto result = research::context_snapshot(store_, session_id, limits_.context_budget_bytes / 3);
    const auto checkpoints = store_.records(session_id, "context_checkpoint");
    result["checkpoint_id"] = checkpoints.empty() ? json_t(nullptr) : checkpoints.back().at("id"); result["ok"] = true; return result;
}
harness::json_t harness::c_runtime::dispatch(const std::string& session_id, const std::string& tool, const harness::json_t& arguments, const std::string& call_id, const std::string& run_id) {
    if (!research::is_session_tool(tool)) return dispatch_native(session_id, tool, arguments, call_id);
    try {
        return research::session_tool(store_, session_id, tool, arguments, limits_, cancelled_, run_id, [&](const json_t& experiment) {
            return dispatch_native(session_id, experiment.at("tool"), experiment.at("arguments"), call_id, experiment);
        });
    } catch (const std::exception& error) { return {{"ok", false}, {"error", error.what()}}; }
}
harness::json_t harness::c_runtime::dispatch_native(const std::string& session_id, const std::string& tool, const harness::json_t& arguments, const std::string& call_id, const harness::json_t& experiment) {
    const auto session = store_.session(session_id);
    const auto directory = std::filesystem::path(widen(session.at("working_directory")));
    auto resolved = arguments;
    bool identity_conflict = false;
    const auto& target = session.at("target_info");
    if (target.at("kind") == "process" && resolved.is_object()) {
        auto pin = [&](json_t& value, const char* pid_key, const char* time_key) {
            if (value.is_object() && value.contains(pid_key) && value.at(pid_key) == target.at("pid")) {
                if (value.contains(time_key) && value.at(time_key) != target.at("creation_time")) identity_conflict = true;
                value[time_key] = target.at("creation_time");
            }
        };
        if (tool == "process_info" || tool == "process_modules" || tool == "process_threads" || tool == "token_info" || tool == "debug_attach" || tool == "dump_process") pin(resolved, "pid", "creation_time");
        if (tool == "security_descriptor" || tool == "security_access_check") {
            if (resolved.contains("target") && resolved.at("target").is_object() && resolved.at("target").contains("kind") && resolved.at("target").at("kind") == "process") pin(resolved["target"], "pid", "creation_time");
            pin(resolved, "token_pid", "token_creation_time");
        }
    }
    const json_t task = {{"state", "queued"}, {"tool", tool}, {"arguments", resolved}, {"requested_arguments", arguments},
        {"call_id", call_id}, {"working_directory", path_text(directory)}, {"limits", config_.at("limits")},
        {"execution_context", config_.at("execution_context")}, {"queued", timestamp()}};
    const auto linkage = experiment.is_null() ? json_t{{"task_id", store_.append(session_id, "task", task)}} : store_.begin_experiment(session_id, experiment, task);
    const auto id = linkage.at("task_id").get<std::string>();
    return scheduler_.schedule([this, session_id, tool, arguments = std::move(resolved), directory, id, identity_conflict, linkage] {
        store_.update_task(id, task_state_t::running);
        std::atomic_bool operation_cancelled{cancelled_.load()}, timed_out{false};
        const auto start = std::chrono::steady_clock::now();
        std::jthread watcher([&](std::stop_token stop) {
            while (!stop.stop_requested()) {
                if (cancelled_.load()) { operation_cancelled.store(true); return; }
                if (std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(limits_.operation_timeout_ms)) {
                    timed_out.store(true); operation_cancelled.store(true); return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });
        auto workspace = research::is_research_tool(tool) ? store_.task_workspace(session_id, id) : std::filesystem::path{};
        auto result = identity_conflict ? windows::c_windows_error("Supplied process identity differs from the bound session", ERROR_INVALID_PARAMETER).result() :
            windows::execute_tool(tool, arguments, directory, limits_, operation_cancelled, workspace);
        watcher.request_stop(); watcher.join();
        if (cancelled_.load()) { result["cancelled"] = true; result["ok"] = false; }
        if (timed_out.load()) { result["timed_out"] = true; result["cancelled"] = false; result["ok"] = false; }
        auto state = cancelled_.load() ? task_state_t::cancelled : result.value("ok", false) ? task_state_t::succeeded : task_state_t::failed;
        if (linkage.contains("experiment_id")) result["experiment_id"] = linkage.at("experiment_id");
        return store_.complete_task(session_id, id, state, std::move(result));
    }).get();
}
harness::json_t harness::c_runtime::investigate(const std::string& session_id, const std::string& goal, const std::string& profile_name,
    std::shared_ptr<harness::ai::c_http_transport> transport) {
    ai::c_orchestrator orchestrator(store_, config_, cancelled_, [this](const std::string& session, const std::string& tool,
        const json_t& arguments, const std::string& call_id, const std::string& run_id) {
        return dispatch(session, tool, arguments, call_id, run_id);
    });
    return orchestrator.investigate(session_id, goal, profile_name, std::move(transport));
}
