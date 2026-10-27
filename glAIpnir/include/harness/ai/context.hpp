#pragma once
#include "harness/ai/model.hpp"
#include "harness/storage/store.hpp"

namespace harness::ai {
struct context_view_t {
    std::vector<message_t> messages;
    std::string checkpoint_id;
    std::size_t bytes = 0;
};
class c_context_builder {
public:
    explicit c_context_builder(storage::c_evidence_store& store) : store_(store) {}
    context_view_t build(const std::string& session_id, const std::string& goal_message_id, const std::string& system,
        const std::string& provider, const limits_t& limits);
private:
    storage::c_evidence_store& store_;
};
}
