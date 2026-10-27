#include "windows_support.hpp"
#include "harness/research/session.hpp"
#include "harness/research/backend.hpp"
#include "harness/ai/context.hpp"
#include <functional>
#include <set>
#include <fstream>
#include <sqlite3.h>

static harness::json_t profile_config(const std::string& provider) {
    return {{"profiles", {{"test", {{"provider", provider}, {"model", "fixture-model"}, {"endpoint", "http://127.0.0.1:1/model"}, {"key_env", ""}}}}}};
}
static harness::json_t seed_hypotheses(const std::filesystem::path& location, const std::string& session) {
    sqlite3* pointer{};
    if (sqlite3_open(harness::path_text(location / "sessions.sqlite3").c_str(), &pointer) != SQLITE_OK) { sqlite3_close(pointer); throw std::runtime_error("Cannot open fixture database"); }
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(pointer, sqlite3_close);
    harness::tests::check(sqlite3_exec(database.get(), "BEGIN", nullptr, nullptr, nullptr) == SQLITE_OK, "begin fixture transaction");
    sqlite3_stmt* raw{};
    harness::tests::check(sqlite3_prepare_v2(database.get(), "INSERT INTO records(id,session_id,kind,data,created) VALUES(?,?,'hypothesis','{\"text\":\"Fixture\",\"observation_ids\":[],\"status\":\"open\",\"verified\":false}','fixture')", -1, &raw, nullptr) == SQLITE_OK, "prepare dependency fixtures");
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw, sqlite3_finalize); harness::json_t ids = harness::json_t::array();
    for (int index = 0; index < 4096; ++index) {
        const auto id = harness::new_id(); ids.push_back(id);
        harness::tests::check(sqlite3_bind_text(statement.get(), 1, id.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_text(statement.get(), 2, session.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(statement.get()) == SQLITE_DONE, "insert dependency fixture");
        sqlite3_reset(statement.get()); sqlite3_clear_bindings(statement.get());
    }
    statement.reset(); harness::tests::check(sqlite3_exec(database.get(), "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK, "commit dependency fixtures"); return ids;
}
static harness::json_t tool_reply(const std::string& provider, const std::string& name, const harness::json_t& arguments) {
    if (provider == "openai") return {{"status", "completed"}, {"output", {
        {{"type", "reasoning"}, {"id", "loop_reasoning"}, {"summary", harness::json_t::array()}, {"encrypted_content", "loop-opaque-reasoning"}},
        {{"type", "function_call"}, {"call_id", harness::new_id()}, {"name", name}, {"arguments", harness::dump_json(arguments)}}}}};
    if (provider == "anthropic") return {{"stop_reason", "tool_use"}, {"content", {{{"type", "tool_use"}, {"id", harness::new_id()}, {"name", name}, {"input", arguments}}}}};
    return {{"done", true}, {"message", {{"role", "assistant"}, {"content", ""}, {"tool_calls", {{{"function", {{"name", name}, {"arguments", arguments}}}}}}}}};
}
static harness::json_t final_reply(const std::string& provider) {
    if (provider == "openai") return {{"status", "completed"}, {"output", {{{"type", "message"}, {"role", "assistant"}, {"content", {{{"type", "output_text"}, {"text", "Evidence collected; assessment remains unverified."}}}}}}}};
    if (provider == "anthropic") return {{"stop_reason", "end_turn"}, {"content", {{{"type", "text"}, {"text", "Evidence collected; assessment remains unverified."}}}}};
    return {{"done", true}, {"message", {{"role", "assistant"}, {"content", "Evidence collected; assessment remains unverified."}}}};
}
class c_script_transport final : public harness::ai::c_http_transport {
public:
    explicit c_script_transport(std::function<harness::json_t(const harness::json_t&, unsigned)> respond) : respond_(std::move(respond)) {}
    harness::json_t post(const std::string&, const harness::ai::headers_t&, const harness::json_t& body, int, const std::atomic_bool&) override {
        requests.push_back(body); return respond_(body, static_cast<unsigned>(requests.size() - 1));
    }
    std::vector<harness::json_t> requests;
private:
    std::function<harness::json_t(const harness::json_t&, unsigned)> respond_;
};
static std::shared_ptr<c_script_transport> workflow(harness::storage::c_evidence_store& store, const std::string& session,
    const std::string& provider, const std::filesystem::path& fixture) {
    return std::make_shared<c_script_transport>([&, provider, session, fixture](const harness::json_t& body, unsigned turn) {
        const auto wire = harness::dump_json(body);
        harness::tests::check(wire.find("hypothesis_create") != std::string::npos && wire.find("evidence_read") != std::string::npos &&
            wire.find("fuzz_run") != std::string::npos && wire.find("\"name\":\"context_import\"") == std::string::npos, "combined native/session tools without implicit import");
        if (turn == 0) return tool_reply(provider, "file_metadata", {{"path", harness::path_text(fixture)}});
        if (turn == 1) {
            const auto observation = store.records(session, "observation").back().at("id");
            harness::tests::check(wire.find(observation.get<std::string>()) != std::string::npos, "observation reference reaches the model");
            return tool_reply(provider, "hypothesis_create", {{"text", "The fixture exits normally and has stable bytes."}, {"observation_ids", {observation}}});
        }
        const auto hypothesis = store.records(session, "hypothesis").back().at("id");
        if (turn == 2) return tool_reply(provider, "experiment_run", {{"hypothesis_id", hypothesis}, {"tool", "debug_run"},
            {"arguments", {{"executable", harness::path_text(fixture)}, {"arguments", {"normal"}}, {"entry_breakpoint", false}}}, {"expected_outcome", "Normal exit with status zero"}});
        if (turn == 3 || turn == 5) {
            harness::json_t ids = harness::json_t::array(); for (const auto& experiment : store.records(session, "experiment")) ids.push_back(experiment.at("id"));
            return tool_reply(provider, "hypothesis_assess", {{"hypothesis_id", hypothesis}, {"experiment_ids", ids},
                {"status", "supported"}, {"conclusion", "The recorded measurements support the hypothesis; no vulnerability is verified."}});
        }
        if (turn == 4) {
            const auto assessment = store.records(session, "assessment").back().at("id").get<std::string>();
            harness::tests::check(wire.find(assessment) != std::string::npos, "assessment informs the next experiment");
            return tool_reply(provider, "experiment_run", {{"hypothesis_id", hypothesis}, {"tool", "file_sha256"},
                {"arguments", {{"path", harness::path_text(fixture)}}}, {"expected_outcome", "A measured SHA-256 for comparison"}});
        }
        return final_reply(provider);
    });
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    const auto fixture = std::filesystem::absolute(argv[1]); const auto root = std::filesystem::current_path() / L"research-loop-data" / harness::widen(harness::new_id());
    std::filesystem::create_directories(root); int failures = 0; std::atomic_bool cancelled{false};
    auto test = [&](const std::string& name, auto function) {
        try { function(); std::cout << "PASS " << name << std::endl; }
        catch (const std::exception& error) { ++failures; std::cerr << "FAIL " << name << ": " << error.what() << std::endl; }
    };
    for (const auto* provider_name : {"openai", "anthropic", "ollama"}) {
        const std::string provider = provider_name;
        test(provider + " structured research, restart and provider switching", [&] {
            const auto location = root / harness::widen(provider); std::string session, hypothesis;
            {
                harness::storage::c_evidence_store store(location); auto config = profile_config(provider); config["limits"] = {{"max_experiments", 2}};
                harness::c_runtime runtime(store, config, cancelled); session = runtime.create_session(fixture);
                auto transport = workflow(store, session, provider, fixture); const auto result = runtime.investigate(session, "Test a hypothesis about this fixture", "test", transport);
                harness::tests::check(result.at("ok") == true && result.at("turns") == 7, "complete research loop: " + harness::dump_json(result));
                harness::tests::check(store.records(session, "experiment").size() == 2 && store.records(session, "assessment").size() == 2 &&
                    store.records(session, "task").size() == 3 && store.records(session, "observation").size() == 3, "distinct persisted research and measurements");
                hypothesis = store.records(session, "hypothesis").back().at("id");
                const auto current = harness::research::research_record(store, session, hypothesis);
                harness::tests::check(current.at("data").at("status") == "supported" && current.at("data").at("verified") == false && store.records(session, "finding").empty(), "assessment never promotes a finding");
                for (const auto& experiment : store.records(session, "experiment")) {
                    const auto task = store.record(session, experiment.at("data").at("task_id"));
                    harness::tests::check(experiment.at("data").at("state") == "succeeded" && task.at("data").at("experiment_id") == experiment.at("id"), "bidirectional experiment/task linkage");
                }
                if (provider == "openai") harness::tests::check(harness::dump_json(transport->requests[2]).find("loop-opaque-reasoning") != std::string::npos, "retained native reasoning continuation");
            }
            harness::storage::c_evidence_store reopened(location); const auto switched = provider == "anthropic" ? std::string("ollama") : std::string("anthropic");
            harness::c_runtime resumed(reopened, profile_config(switched), cancelled);
            auto transport = std::make_shared<c_script_transport>([&](const harness::json_t& body, unsigned) {
                const auto wire = harness::dump_json(body);
                harness::tests::check(wire.find(hypothesis) != std::string::npos && wire.find("supported") != std::string::npos && wire.find("Continue using stored research") != std::string::npos,
                    "restart reconstructs research context for another provider"); return final_reply(switched);
            });
            harness::tests::check(resumed.investigate(session, "Continue using stored research", "test", transport).at("ok") == true, "resume with another adapter");
            harness::tests::check(reopened.records(session, "task").size() == 3 && !reopened.records(session, "context_checkpoint").empty(), "resume creates no duplicate experiments");
            reopened.export_session(session, root / harness::widen(provider + "-export"));
        });
    }
    test("experiment budget and incomplete model replies preserve evidence", [&] {
        harness::storage::c_evidence_store store(root / L"budget"); auto config = profile_config("ollama"); config["limits"] = {{"max_experiments", 1}};
        harness::c_runtime runtime(store, config, cancelled); const auto id = runtime.create_session(fixture); auto transport = workflow(store, id, "ollama", fixture);
        harness::tests::check(runtime.investigate(id, "Bound the experiment count", "test", transport).at("ok") == true && store.records(id, "experiment").size() == 1 &&
            store.records(id, "task").size() == 2, "exhausted budget rejects further native execution");
        harness::tests::check(harness::dump_json(transport->requests[5]).find("experiment limit") != std::string::npos, "budget error returned to the model");
        const auto incomplete = runtime.create_session(fixture);
        auto interrupted = std::make_shared<c_script_transport>([&](const harness::json_t&, unsigned) {
            auto reply = tool_reply("ollama", "hypothesis_create", {{"text", "Must not execute"}}); reply["done_reason"] = "length"; return reply;
        });
        harness::tests::check(runtime.investigate(incomplete, "Incomplete reply", "test", interrupted).at("ok") == false && store.records(incomplete, "hypothesis").empty(), "incomplete replies never mutate research");
        const auto oversized = runtime.create_session(fixture); config["limits"]["context_budget_bytes"] = 4096; harness::c_runtime bounded(store, config, cancelled);
        auto unused = std::make_shared<c_script_transport>([](const harness::json_t&, unsigned) -> harness::json_t { throw std::runtime_error("HTTP must not run"); });
        harness::tests::check(bounded.investigate(oversized, std::string(8192, 'x'), "test", unused).at("ok") == false && unused->requests.empty() &&
            !store.records(oversized, "message").empty(), "oversized required context stops before HTTP and preserves history");
    });
    test("reference validation, native errors and evidence integrity", [&] {
        harness::storage::c_evidence_store store(root / L"validation"); harness::c_runtime runtime(store, harness::json_t::object(), cancelled);
        const auto id = runtime.create_session(fixture), foreign = runtime.create_session(fixture);
        const auto observation = runtime.dispatch(id, "file_metadata", {{"path", harness::path_text(fixture)}});
        harness::tests::check(runtime.dispatch(foreign, "hypothesis_create", {{"text", "Wrong session"}, {"observation_ids", {observation.at("observation_id")}}}).at("ok") == false, "cross-session IDs require explicit import");
        const auto hypothesis = runtime.dispatch(id, "hypothesis_create", {{"text", "Local hypothesis"}}).at("hypothesis_id");
        auto run = [&](const std::string& tool, harness::json_t arguments) { return runtime.dispatch(id, "experiment_run", {{"hypothesis_id", hypothesis}, {"tool", tool}, {"arguments", arguments}, {"expected_outcome", "Measured outcome"}}); };
        harness::tests::check(run("experiment_run", harness::json_t::object()).at("ok") == false && run("file_metadata", harness::json_t::object()).at("ok") == false && store.records(id, "experiment").empty(), "invalid and nested tools rejected before persistence");
        auto failed = run("debug_run", {{"executable", harness::path_text(root / L"missing.exe")}, {"arguments", harness::json_t::array()}});
        harness::tests::check(failed.at("ok") == false && failed.contains("experiment_id") && store.records(id, "experiment").back().at("data").at("state") == "failed", "native failures preserve the experiment and observation");
        const auto other = runtime.dispatch(id, "hypothesis_create", {{"text", "Other hypothesis"}}).at("hypothesis_id");
        harness::tests::check(runtime.dispatch(id, "hypothesis_assess", {{"hypothesis_id", other}, {"experiment_ids", {failed.at("experiment_id")}}, {"status", "supported"}, {"conclusion", "Wrong linkage"}}).at("ok") == false, "assessments cannot mix hypotheses");
        cancelled.store(true); harness::tests::check(run("file_metadata", {{"path", harness::path_text(fixture)}}).at("cancelled") == true, "cancellation prevents new experiment execution"); cancelled.store(false);
        auto read = runtime.dispatch(id, "evidence_read", {{"artifact_id", observation.at("artifact_id")}, {"length", 32}});
        harness::tests::check(read.at("ok") == true && read.at("bytes_read") == 32 && read.at("hex").get<std::string>().size() == 64, "bounded hashed artifact reads");
        harness::write_text(root / L"validation" / harness::widen(observation.at("artifact")), "tampered");
        harness::tests::check(runtime.dispatch(id, "evidence_read", {{"artifact_id", observation.at("artifact_id")}}).at("ok") == false, "tampered evidence is rejected");
    });
    test("compaction preserves complete exchanges, native blocks and original history", [&] {
        harness::storage::c_evidence_store store(root / L"context"); const auto id = store.create_session(fixture, harness::json_t::object());
        for (int index = 0; index < 12; ++index) {
            harness::message_t assistant; assistant.role = "assistant"; const auto call_id = harness::new_id(); assistant.calls.push_back({call_id, "file_metadata", {{"path", harness::path_text(fixture)}}});
            assistant.native = {{"provider", "openai"}, {"output", {{{"type", "reasoning"}, {"encrypted_content", "preserved-context-reasoning"}},
                {{"type", "function_call"}, {"call_id", call_id}, {"name", "file_metadata"}, {"arguments", harness::dump_json(assistant.calls.front().arguments)}}}}};
            store.append(id, "message", harness::message_json(assistant));
            harness::message_t result; result.role = "tool"; result.call_id = call_id; result.tool_name = "file_metadata"; result.text = harness::dump_json({{"ok", true}, {"detail", std::string(20000, 'a')}});
            store.append(id, "message", harness::message_json(result));
        }
        harness::message_t user; user.role = "user"; user.text = "Continue this goal"; const auto goal = store.append(id, "message", harness::message_json(user));
        harness::limits_t limits; limits.context_budget_bytes = 8192; limits.context_recent_exchanges = 2; harness::ai::c_context_builder builder(store);
        const auto view = builder.build(id, goal, "Research policy", "openai", limits); const auto checkpoint = store.record(id, view.checkpoint_id);
        harness::tests::check(view.bytes <= 8192 && checkpoint.at("data").at("archived_exchanges") == 10 && store.records(id, "message").size() == 25, "bounded context archives complete exchanges without deleting messages");
        harness::ai::c_model_client client(harness::parse_profile(profile_config("openai"), "test")); const auto body = client.request_body(view.messages, harness::research::all_tool_definitions());
        unsigned calls = 0, outputs = 0;
        for (const auto& item : body.at("input")) { if (item.value("type", "") == "function_call") ++calls; if (item.value("type", "") == "function_call_output") ++outputs; }
        harness::tests::check(calls == 2 && outputs == 2 && harness::dump_json(body).find("preserved-context-reasoning") != std::string::npos && store.records(id, "context_projection").size() == 2, "tool pairs and provider continuation remain intact");
        const auto repeated = builder.build(id, goal, "Research policy", "openai", limits);
        harness::tests::check(repeated.checkpoint_id == view.checkpoint_id && store.records(id, "context_projection").size() == 2, "checkpoint and evidence projections are reused deterministically");
        const auto hypothesis = store.append(id, "hypothesis", {{"text", "An older active hypothesis"}, {"status", "open"}, {"verified", false}});
        for (int index = 0; index < 100; ++index) store.append(id, "observation", {{"task_id", "fixture"}, {"data", {{"ok", true}}}});
        const auto state = harness::research::context_snapshot(store, id, 1024);
        harness::tests::check(harness::dump_json(state).find(hypothesis) != std::string::npos && state.at("omitted").get<unsigned>() > 0, "active hypotheses outrank a flood of newer observations");
    });
    test("imports snapshot related research and remain independent of source artifacts", [&] {
        const auto location = root / L"imports"; harness::storage::c_evidence_store store(location); harness::c_runtime runtime(store, harness::json_t::object(), cancelled);
        const auto source = runtime.create_session(fixture), destination = runtime.create_session(fixture);
        const auto first = runtime.dispatch(source, "file_metadata", {{"path", harness::path_text(fixture)}});
        const auto hypothesis = runtime.dispatch(source, "hypothesis_create", {{"text", "Reusable research"}, {"observation_ids", {first.at("observation_id")}}}).at("hypothesis_id");
        const auto experiment = runtime.dispatch(source, "experiment_run", {{"hypothesis_id", hypothesis}, {"tool", "debug_run"},
            {"arguments", {{"executable", harness::path_text(fixture)}, {"arguments", {"normal"}}, {"entry_breakpoint", false}}}, {"expected_outcome", "Exit zero"}});
        harness::tests::check(experiment.at("ok") == true, "source experiment completes");
        runtime.dispatch(source, "hypothesis_assess", {{"hypothesis_id", hypothesis}, {"experiment_ids", {experiment.at("experiment_id")}}, {"status", "supported"}, {"conclusion", "Measured normal exit"}});
        store.append(source, "assessment", {{"hypothesis_id", hypothesis}, {"experiment_ids", {experiment.at("experiment_id")}},
            {"observation_ids", {experiment.at("observation_id")}}, {"status", "inconclusive"}, {"conclusion", "Later assessment supersedes the first"}, {"verified", false}}, "00000000000000000000000000000001");
        const auto selection = harness::json_t::array({hypothesis});
        const auto imported = store.import_research(destination, source, selection, cancelled);
        harness::tests::check(imported.at("ok") == true && store.records(destination, "hypothesis").size() == 1 && store.records(destination, "assessment").size() == 2, "linked research imported as one snapshot");
        const auto imported_hypothesis = store.records(destination, "hypothesis").front();
        harness::tests::check(imported_hypothesis.at("id") != hypothesis && imported_hypothesis.at("data").at("origin").at("record_id") == hypothesis &&
            imported_hypothesis.at("data").at("background") == false && harness::research::research_record(store, destination, imported_hypothesis.at("id")).at("data").at("status") == "inconclusive", "IDs remapped with provenance and chronological assessment order");
        harness::tests::check(runtime.dispatch(destination, "experiment_run", {{"hypothesis_id", imported_hypothesis.at("id")}, {"tool", "file_metadata"},
            {"arguments", {{"path", harness::path_text(fixture)}}}, {"expected_outcome", "Do not mutate imported hypotheses"}}).at("ok") == false, "imported hypotheses remain immutable");
        const auto other_file = root / L"different.bin"; harness::write_text(other_file, "different target"); const auto other = runtime.create_session(other_file);
        harness::tests::check(store.import_research(other, source, selection, cancelled).at("ok") == true && store.records(other, "hypothesis").front().at("data").at("background") == true, "different-target context is labeled background");
        const auto chained = runtime.create_session(other_file);
        const auto other_selection = harness::json_t::array({store.records(other, "hypothesis").front().at("id")});
        const auto reimported = store.import_research(chained, other, other_selection, cancelled);
        harness::tests::check(reimported.at("ok") == true && store.records(chained, "hypothesis").front().at("data").at("background") == true &&
            store.records(chained, "hypothesis").front().at("data").at("origin").at("previous").at("session_id") == source,
            "chained imports preserve background status and original provenance");
        const auto snapshot_destination = runtime.create_session(fixture);
        const auto snapshot_import = store.import_research(snapshot_destination, destination, harness::json_t::array({imported.at("import_id")}), cancelled);
        harness::tests::check(snapshot_import.at("ok") == true && store.records(snapshot_destination, "hypothesis").size() == 1 &&
            store.records(snapshot_destination, "context_import").size() == 2, "a previous import snapshot can itself be imported with intact dependencies");
        auto artifacts = store.records(source, "artifact"); std::string last_id;
        for (const auto& artifact : artifacts) if (artifact.at("id").get<std::string>() > last_id) last_id = artifact.at("id");
        const auto corrupted = store.record(source, last_id); harness::write_text(location / harness::widen(corrupted.at("data").at("path")), "tampered source");
        const auto failed = store.import_research(destination, source, selection, cancelled);
        harness::tests::check(failed.at("ok") == false && store.records(destination, "hypothesis").size() == 1 && store.records(destination, "context_import").size() == 1, "failed import publishes no research snapshot");
        const auto exported = root / L"import-export"; store.export_session(destination, exported);
        for (const auto& artifact : store.records(destination, "artifact")) {
            const auto& data = artifact.at("data"); harness::tests::check(harness::sha256(exported / harness::widen(data.at("path"))) == data.at("sha256").get<std::string>(), "destination export uses its own verified files");
        }
        cancelled.store(true); harness::tests::fails([&] { store.import_research(destination, source, selection, cancelled); }, "cancelled imports do not publish context"); cancelled.store(false);
        harness::tests::fails([&] { store.import_research(destination, source, harness::json_t::array(), cancelled); }, "empty imports rejected");
        harness::json_t too_many = harness::json_t::array(); for (int index = 0; index < 101; ++index) too_many.push_back(hypothesis);
        harness::tests::fails([&] { store.import_research(destination, source, too_many, cancelled); }, "selection cap enforced");
    });
    test("import dependency caps, missing links and escaping paths fail before publication", [&] {
        const auto location = root / L"import-limits"; harness::storage::c_evidence_store store(location);
        const auto source = store.create_session(fixture, harness::json_t::object()), destination = store.create_session(fixture, harness::json_t::object());
        const auto ids = seed_hypotheses(location, source);
        const auto wrapper = store.append(source, "context_import", {{"record_ids", ids}, {"source_session_id", "fixture"}, {"same_target", true}});
        bool limited = false;
        try { store.import_research(destination, source, harness::json_t::array({wrapper}), cancelled); }
        catch (const std::exception& error) { limited = std::string(error.what()).find("dependency limit") != std::string::npos; }
        harness::tests::check(limited && store.records(destination).empty(), "dependency expansion is capped before copying or publication");
        const auto broken = store.append(source, "hypothesis", {{"text", "Broken reference fixture"}, {"observation_ids", {"missing-observation"}}});
        harness::tests::fails([&] { store.import_research(destination, source, harness::json_t::array({broken}), cancelled); }, "missing dependencies are rejected");
        const auto escaping = store.append(source, "artifact", {{"path", "../outside.bin"}, {"size", 0}, {"sha256", "fixture"}});
        const auto result = store.import_research(destination, source, harness::json_t::array({escaping}), cancelled);
        harness::tests::check(result.at("ok") == false && store.records(destination, "context_import").empty(), "escaping paths cannot publish imported records");
    });
    test("recovery finalizes linked experiments and does not publish partial imports", [&] {
        const auto location = root / L"recovery"; std::string id, experiment;
        {
            harness::storage::c_evidence_store store(location); id = store.create_session(fixture, harness::json_t::object());
            const auto linkage = store.begin_experiment(id, {{"hypothesis_id", "recovery-fixture"}, {"tool", "file_metadata"}}, {{"tool", "file_metadata"}}); experiment = linkage.at("experiment_id");
            auto task = store.append(id, "task", {{"state", "running"}, {"tool", "context_import"}}); const auto workspace = store.task_workspace(id, task);
            harness::write_text(workspace / "crash.json", harness::dump_json({{"signature", "unpublished-import"}, {"exception_code", EXCEPTION_ACCESS_VIOLATION}}));
            harness::message_t assistant; assistant.role = "assistant"; assistant.calls.push_back({"pending", "experiment_run", harness::json_t::object()}); store.append(id, "message", harness::message_json(assistant));
        }
        {
            harness::storage::c_evidence_store recovered(location);
            harness::tests::check(recovered.record(id, experiment).at("data").at("state") == "interrupted" && recovered.records(id, "context_import").empty() && recovered.records(id, "crash").empty(), "unfinished experiment interrupted and copied manifests not promoted");
            harness::tests::check(recovered.records(id, "artifact").size() == 2 && recovered.records(id, "message").back().at("data").at("role") == "tool", "partial bytes preserved and unresolved model call resolved without execution");
        }
        harness::storage::c_evidence_store reopened(location); harness::tests::check(reopened.records(id, "task").size() == 2 && reopened.records(id, "artifact").size() == 2, "second reopen is idempotent");
    });
    std::cout << "Failures: " << failures << '\n'; return failures ? 1 : 0;
}
