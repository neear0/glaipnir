#include "harness/research/session.hpp"
#include "harness/windows/tools.hpp"
#include <set>
#include <map>
#include <algorithm>

static harness::json_t schema(harness::json_t properties, harness::json_t required) {
    return {{"type", "object"}, {"properties", properties}, {"required", required}, {"additionalProperties", false}};
}
static harness::json_t references(unsigned minimum = 0) {
    return {{"type", "array"}, {"items", {{"type", "string"}, {"minLength", 1}, {"maxLength", 128}}}, {"minItems", minimum}, {"maxItems", 100}};
}
harness::json_t harness::research::session_definitions() {
    const json_t text = {{"type", "string"}, {"minLength", 1}, {"maxLength", 16384}}, id = {{"type", "string"}, {"minLength", 1}, {"maxLength", 128}};
    return json_t::array({
        {{"name", "hypothesis_create"}, {"description", "Record an unverified research hypothesis linked to stored observations."},
            {"parameters", schema({{"text", text}, {"observation_ids", references()}}, {"text"})}},
        {{"name", "experiment_run"}, {"description", "Persist and execute one native tool experiment for a local hypothesis; never retries automatically."},
            {"parameters", schema({{"hypothesis_id", id}, {"tool", id}, {"arguments", {{"type", "object"}}}, {"expected_outcome", text}}, {"hypothesis_id", "tool", "arguments", "expected_outcome"})}},
        {{"name", "hypothesis_assess"}, {"description", "Record an unverified interpretation of completed experiments. Supported does not mean verified."},
            {"parameters", schema({{"hypothesis_id", id}, {"experiment_ids", references(1)}, {"conclusion", text},
                {"status", {{"type", "string"}, {"enum", {"supported", "refuted", "inconclusive"}}}}}, {"hypothesis_id", "experiment_ids", "conclusion", "status"})}},
        {{"name", "research_records"}, {"description", "Page through research record summaries; use research_record_get for details."},
            {"parameters", schema({{"kind", {{"type", "string"}, {"enum", {"hypothesis", "experiment", "assessment", "observation", "artifact", "crash", "context_import", "context_checkpoint", "task", "summary"}}}},
                {"offset", {{"type", "integer"}, {"minimum", 0}, {"maximum", 1000000000}}}, {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 100}}}}, json_t::array())}},
        {{"name", "research_record_get"}, {"description", "Read a research record within this session, including its evidence references and provenance."},
            {"parameters", schema({{"record_id", id}}, {"record_id"})}},
        {{"name", "evidence_read"}, {"description", "Read bounded artifact bytes after verifying the persisted size and SHA-256."},
            {"parameters", schema({{"artifact_id", id}, {"offset", {{"type", "integer"}, {"minimum", 0}}},
                {"length", {{"type", "integer"}, {"minimum", 1}, {"maximum", 65536}}}}, {"artifact_id"})}}
    });
}
harness::json_t harness::research::all_tool_definitions() {
    auto result = windows::tool_definitions(); for (const auto& definition : session_definitions()) result.push_back(definition); return result;
}
bool harness::research::is_session_tool(const std::string& name) {
    for (const auto& definition : session_definitions()) if (definition.at("name") == name) return true;
    return false;
}
static bool research_kind(const std::string& kind) {
    static const std::set<std::string> kinds = {"hypothesis", "experiment", "assessment", "observation", "artifact", "crash", "context_import", "context_checkpoint", "task", "summary"};
    return kinds.contains(kind);
}
harness::json_t harness::research::research_record(harness::storage::c_evidence_store& store, const std::string& session_id, const std::string& id) {
    auto record = store.record(session_id, id);
    if (!research_kind(record.at("kind"))) throw std::runtime_error("Record is not research evidence");
    if (record.at("kind") == "hypothesis") {
        record["data"]["status"] = "open";
        for (const auto& assessment : store.records(session_id, "assessment")) if (assessment.at("data").at("hypothesis_id") == id) {
            record["data"]["status"] = assessment.at("data").at("status"); record["data"]["assessment_id"] = assessment.at("id");
        }
    }
    return record;
}
static harness::json_t summary(const harness::json_t& record) {
    const auto& data = record.at("data"); harness::json_t result = {{"id", record.at("id")}, {"kind", record.at("kind")}};
    for (const auto* key : {"text", "state", "status", "hypothesis_id", "task_id", "tool", "observation_ids", "experiment_ids", "artifact_id", "path", "size", "sha256", "imported", "background", "origin"})
        if (data.contains(key)) result[key] = data.at(key);
    return result;
}
static std::string excerpt(const std::string& text, std::size_t limit) {
    if (text.size() <= limit) return text;
    while (limit && (static_cast<unsigned char>(text[limit]) & 0xc0) == 0x80) --limit;
    return text.substr(0, limit) + "...";
}
harness::json_t harness::research::context_snapshot(harness::storage::c_evidence_store& store, const std::string& session_id, std::size_t budget) {
    store.session(session_id); json_t result = {{"records", json_t::array()}, {"omitted", 0}, {"verified", false}};
    auto records = store.records(session_id); std::map<std::string, json_t> latest;
    for (const auto& record : records) if (record.at("kind") == "assessment") latest[record.at("data").at("hypothesis_id")] = record;
    std::vector<std::pair<int, json_t>> candidates;
    for (auto iterator = records.rbegin(); iterator != records.rend(); ++iterator) {
        auto record = *iterator; const auto kind = record.at("kind").get<std::string>();
        if (kind != "hypothesis" && kind != "experiment" && kind != "assessment" && kind != "context_import" && kind != "observation") continue;
        if (kind == "hypothesis") {
            const auto id = record.at("id").get<std::string>(); record["data"]["status"] = latest.contains(id) ? latest.at(id).at("data").at("status") : json_t("open");
        }
        auto entry = summary(record);
        for (const auto* key : {"text", "conclusion", "expected_outcome"}) if (record.at("data").contains(key))
            entry[key] = excerpt(record.at("data").at(key), (std::max)(std::size_t{64}, (std::min)(std::size_t{512}, budget / 4)));
        if (entry.contains("origin")) entry["origin"] = {{"session_id", entry.at("origin").at("session_id")}, {"record_id", entry.at("origin").at("record_id")}};
        for (const auto* key : {"observation_ids", "experiment_ids"}) if (entry.contains(key) && entry.at(key).size() > 4) {
            entry[std::string(key) + "_count"] = entry.at(key).size();
            entry[key].erase(entry[key].begin() + 4, entry[key].end());
        }
        if (kind == "observation") {
            entry["result"] = json_t::object();
            const auto& data = record.at("data").at("data");
            for (const auto* key : {"ok", "outcome", "sha256", "architecture", "exit_code", "reproduced", "artifact_id", "artifact", "task_id", "experiment_id"})
                if (data.contains(key)) entry["result"][key] = data.at(key);
        }
        if (kind == "assessment") entry["status"] = record.at("data").at("status");
        if (kind == "context_import") { entry["source_session_id"] = record.at("data").at("source_session_id"); entry["same_target"] = record.at("data").at("same_target"); }
        int priority = kind == "hypothesis" ? (record.at("data").value("imported", false) ? 3 : (entry.at("status") == "open" || entry.at("status") == "inconclusive" ? 0 : 2)) :
            kind == "assessment" ? 1 : kind == "experiment" ? 4 : kind == "context_import" ? 5 : 6;
        if (kind == "assessment" && latest.at(record.at("data").at("hypothesis_id")).at("id") != record.at("id")) priority = 7;
        candidates.emplace_back(priority, std::move(entry));
    }
    std::stable_sort(candidates.begin(), candidates.end(), [](const auto& first, const auto& second) { return first.first < second.first; });
    for (const auto& [priority, entry] : candidates) {
        (void)priority;
        result["records"].push_back(entry);
        if (dump_json(result).size() > budget) { result["records"].erase(result["records"].end() - 1); result["omitted"] = result.at("omitted").get<unsigned>() + 1; }
    }
    return result;
}
static harness::json_t local_hypothesis(harness::storage::c_evidence_store& store, const std::string& session_id, const std::string& id) {
    const auto record = store.record(session_id, id);
    if (record.at("kind") != "hypothesis" || record.at("data").value("imported", false)) throw std::runtime_error("Expected a local hypothesis; create one from imported observations first");
    return record;
}
harness::json_t harness::research::session_tool(harness::storage::c_evidence_store& store, const std::string& session_id, const std::string& name,
    const harness::json_t& arguments, const harness::limits_t& limits, const std::atomic_bool& cancelled, const std::string& run_id, const experiment_runner_t& run) {
    store.session(session_id);
    for (const auto& definition : session_definitions()) if (definition.at("name") == name) validate_arguments(arguments, definition.at("parameters"));
    if (cancelled.load()) return {{"ok", false}, {"cancelled", true}};
    json_t result;
    if (name == "hypothesis_create") {
        const auto observations = arguments.value("observation_ids", json_t::array());
        for (const auto& id : observations) if (store.record(session_id, id).at("kind") != "observation") throw std::runtime_error("Hypothesis references must identify observations in this session");
        const auto id = store.append(session_id, "hypothesis", {{"text", arguments.at("text")}, {"observation_ids", observations}, {"status", "open"}, {"verified", false}, {"run_id", run_id}});
        result = {{"ok", true}, {"hypothesis_id", id}, {"record", research_record(store, session_id, id)}};
    } else if (name == "experiment_run") {
        local_hypothesis(store, session_id, arguments.at("hypothesis_id"));
        const auto tool = arguments.at("tool").get<std::string>(); windows::validate_tool(tool, arguments.at("arguments"));
        if (dump_json(arguments.at("arguments")).size() > 256 * 1024) throw std::runtime_error("Experiment arguments exceed 256 KiB");
        if (!run_id.empty()) {
            int count = 0; for (const auto& experiment : store.records(session_id, "experiment")) if (experiment.at("data").value("run_id", "") == run_id) ++count;
            if (count >= limits.max_experiments) throw std::runtime_error("Investigation reached its experiment limit");
        }
        auto plan = arguments; plan["run_id"] = run_id; result = run(plan);
    } else if (name == "hypothesis_assess") {
        const auto hypothesis = arguments.at("hypothesis_id").get<std::string>(); local_hypothesis(store, session_id, hypothesis);
        json_t observations = json_t::array();
        for (const auto& id : arguments.at("experiment_ids")) {
            const auto experiment = store.record(session_id, id);
            if (experiment.at("kind") != "experiment" || experiment.at("data").value("imported", false) || experiment.at("data").at("hypothesis_id") != hypothesis)
                throw std::runtime_error("Assessment experiment does not belong to the local hypothesis");
            const auto task = store.record(session_id, experiment.at("data").at("task_id")); const auto state = task.at("data").at("state").get<std::string>();
            if (state == "queued" || state == "running") throw std::runtime_error("Cannot assess an unfinished experiment");
            if (task.at("data").contains("result") && task.at("data").at("result").is_object() && task.at("data").at("result").contains("observation_id"))
                observations.push_back(task.at("data").at("result").at("observation_id"));
        }
        auto data = arguments; data["observation_ids"] = observations; data["verified"] = false; data["run_id"] = run_id;
        const auto id = store.append(session_id, "assessment", data); result = {{"ok", true}, {"assessment_id", id}, {"record", store.record(session_id, id)}};
    } else if (name == "research_record_get") result = {{"ok", true}, {"record", research_record(store, session_id, arguments.at("record_id"))}};
    else if (name == "evidence_read") result = store.read_evidence(session_id, arguments.at("artifact_id"), arguments.value("offset", std::uint64_t{0}), arguments.value("length", std::size_t{4096}), cancelled);
    else if (name == "research_records") {
        auto records = store.records(session_id, arguments.value("kind", "")); const auto offset = arguments.value("offset", std::size_t{0}), limit = arguments.value("limit", std::size_t{20});
        result = {{"ok", true}, {"records", json_t::array()}, {"next_offset", nullptr}};
        std::size_t position = offset;
        for (; position < records.size() && result["records"].size() < limit; ++position) if (research_kind(records[position].at("kind"))) {
            auto record = records[position]; if (record.at("kind") == "hypothesis") record = research_record(store, session_id, record.at("id"));
            result["records"].push_back(summary(record));
        }
        if (position < records.size()) result["next_offset"] = position;
    } else throw std::runtime_error("Unknown research session tool");
    if (dump_json(result).size() > limits.output_limit) {
        const auto artifact = store.save_artifact(session_id, dump_json(result, 2));
        return {{"ok", result.value("ok", false)}, {"output_truncated", true}, {"artifact_id", artifact.record_id}, {"artifact", artifact.path}};
    }
    return result;
}
