#pragma once
#include "harness/ai/context.hpp"
#include <functional>

namespace harness::ai {
using dispatch_t = std::function<json_t(const std::string&, const std::string&, const json_t&, const std::string&, const std::string&)>;
class c_orchestrator {
public:
    c_orchestrator(storage::c_evidence_store& store, json_t config, std::atomic_bool& cancelled, dispatch_t dispatch);
    json_t investigate(const std::string& session_id, const std::string& goal, const std::string& profile,
        std::shared_ptr<c_http_transport> transport);
private:
    storage::c_evidence_store& store_;
    json_t config_;
    limits_t limits_;
    std::atomic_bool& cancelled_;
    dispatch_t dispatch_;
};
}
