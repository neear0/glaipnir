#pragma once
#include "harness/core/util.hpp"
struct sqlite3;

namespace harness::storage {
class c_evidence_store {
public:
    explicit c_evidence_store(std::filesystem::path root);
    ~c_evidence_store();
    c_evidence_store(const c_evidence_store&) = delete;
    c_evidence_store& operator=(const c_evidence_store&) = delete;
    std::string create_session(const std::filesystem::path& target, const json_t& config);
    std::string create_session(const research_target_t& target, const json_t& config);
    json_t list_sessions() const;
    json_t session(const std::string& id) const;
    json_t records(const std::string& session_id, const std::string& kind = "") const;
    std::string append(const std::string& session_id, const std::string& kind, const json_t& data, const std::string& record_id = "");
    json_t record(const std::string& session_id, const std::string& id) const;
    json_t begin_experiment(const std::string& session_id, json_t experiment, json_t task);
    json_t read_evidence(const std::string& session_id, const std::string& artifact_id, std::uint64_t offset, std::size_t length, const std::atomic_bool& cancelled) const;
    json_t import_research(const std::string& destination, const std::string& source, const json_t& ids, const std::atomic_bool& cancelled);
    void update_task(const std::string& id, task_state_t state, const json_t& result = nullptr);
    json_t complete_task(const std::string& session_id, const std::string& task_id, task_state_t state, json_t result, bool register_files = true);
    artifact_t save_artifact(const std::string& session_id, const std::string& content);
    std::filesystem::path task_workspace(const std::string& session_id, const std::string& task_id);
    json_t export_session(const std::string& session_id, const std::filesystem::path& destination) const;
    void recover();
private:
    void execute(const char* sql) const;
    std::filesystem::path artifact_path(const std::string& relative) const;
    std::filesystem::path root_;
    c_handle lock_;
    sqlite3* database_ = nullptr;
};
}
