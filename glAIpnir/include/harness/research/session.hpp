#pragma once
#include "harness/storage/store.hpp"
#include <functional>

namespace harness::research {
using experiment_runner_t = std::function<json_t(const json_t&)>;
json_t session_definitions();
json_t all_tool_definitions();
bool is_session_tool(const std::string& name);
json_t session_tool(storage::c_evidence_store& store, const std::string& session_id, const std::string& name, const json_t& arguments,
    const limits_t& limits, const std::atomic_bool& cancelled, const std::string& run_id, const experiment_runner_t& run);
json_t context_snapshot(storage::c_evidence_store& store, const std::string& session_id, std::size_t budget);
json_t research_record(storage::c_evidence_store& store, const std::string& session_id, const std::string& id);
}
