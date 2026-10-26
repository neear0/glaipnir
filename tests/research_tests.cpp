#include "windows_support.hpp"
#include "harness/research/backend.hpp"
#include <thread>
#include <sstream>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return 2;
    const auto fixture = std::filesystem::absolute(argv[1]);
    const std::string architecture = argc > 2 ? harness::narrow(argv[2]) : "x64";
    const auto root = std::filesystem::current_path() / L"research-test-data" / harness::widen(harness::new_id());
    std::filesystem::create_directories(root);
    int failures = 0;
    auto test = [&](const std::string& name, auto function) {
        try { function(); std::cout << "PASS " << name << std::endl; }
        catch (const std::exception& error) { ++failures; std::cerr << "FAIL " << name << ": " << error.what() << std::endl; }
    };
    std::atomic_bool cancelled{false}; harness::limits_t limits;
    harness::storage::c_evidence_store store(root / L"store"); harness::c_runtime runtime(store, harness::json_t::object(), cancelled);
    const auto session = runtime.create_session(fixture);
    auto execute = [&](const std::string& tool, harness::json_t args) { return runtime.dispatch(session, tool, args); };
    auto run = [&](harness::json_t args) { args["executable"] = harness::path_text(fixture); return execute("debug_run", args); };
    auto evidence = [&](const harness::json_t& result, const std::string& relative) {
        return root / L"store" / harness::widen(result.at("artifact_root")) / harness::widen(relative);
    };
    test("debugger launch, entry breakpoint, stepping, stdout and handled exceptions", [&] {
        auto result = run({{"arguments", {"normal"}}, {"step_count", 2}});
        harness::tests::check(result.at("ok") == true && result.at("outcome") == "exit" && result.at("exit_code") == 0, "normal debug run: " + harness::dump_json(result));
        harness::tests::check(result.at("snapshots").size() >= 3 && result.at("snapshots")[1].at("reason") == "single_step", "entry breakpoint and steps");
        harness::tests::check(harness::research::read_binary(evidence(result, result.at("stdout")), 1024) == "normal\n", "raw stdout artifact");
        auto handled = run({{"arguments", {"handled"}}, {"entry_breakpoint", false}});
        harness::tests::check(handled.at("outcome") == "exit" && handled.at("crashes").empty(), "handled first-chance exception is not a crash");
        auto debug = run({{"arguments", {"debug_strings"}}, {"entry_breakpoint", false}});
        auto trace = harness::dump_json(debug.at("events")); harness::tests::check(trace.find("fixture-debug-string") != std::string::npos && trace.find("\u017elt\u00fd-debug-string") != std::string::npos, "ANSI and Unicode debug output");
    });
    test("one-shot module RVA breakpoint and bounded memory reads", [&] {
        harness::json_t layout_args = {{"executable", harness::path_text(fixture)}, {"arguments", {"layout"}}};
        auto layout = harness::windows::execute_tool("process_launch", layout_args, root, limits, cancelled);
        auto rva = harness::json_t::parse(layout.at("stdout").get<std::string>()).at("marker_rva");
        auto result = run({{"arguments", {"marker"}}, {"entry_breakpoint", false}, {"breakpoints", {{{"rva", rva}}}}, {"step_count", 2},
            {"memory_reads", {{{"address", 1}, {"length", 16}}}}});
        harness::tests::check(result.at("outcome") == "exit" && result.at("exit_code") == 0 && result.at("snapshots").size() >= 3, "custom breakpoint continues correctly: " + harness::dump_json(result));
        harness::tests::check(result.at("snapshots").front().at("instruction").at("rva") == rva && result.at("snapshots").front().at("memory").front().at("complete") == false, "RVA and failed memory read evidence");
        harness::tests::check(result.at("snapshots").front().at("instruction_bytes").at("address") == result.at("snapshots").front().at("instruction").at("address"), "stack walking preserves captured instruction context");
        harness::tests::check(harness::research::read_binary(evidence(result, result.at("stdout")), 1024) == "marker=43\n", "original instruction restored");
    });
    test("unhandled crash, ASLR-normalized signature and native minidump", [&] {
        auto result = run({{"arguments", {"crash"}}, {"entry_breakpoint", false}});
        harness::tests::check(result.at("ok") == true && result.at("outcome") == "crash" && result.at("crashes").size() == 1, "crash collection: " + harness::dump_json(result));
        const auto& crash = result.at("crashes").front();
        harness::tests::check(crash.at("exception_code") == EXCEPTION_ACCESS_VIOLATION && crash.at("signature_normalized") == true && crash.at("dump_result").at("ok") == true, "crash details and minidump");
        auto path = evidence(result, crash.at("minidump"));
        auto inspected = execute("crash_info", {{"path", harness::path_text(path)}});
        harness::tests::check(inspected.at("ok") == true && inspected.at("architecture") == architecture && inspected.at("has_exception") == true &&
            inspected.at("exception").at("code") == EXCEPTION_ACCESS_VIOLATION && inspected.at("threads").size() >= 1, "read actual minidump: " + harness::dump_json(inspected));
        const auto expected_pc = crash.at("snapshot").at("registers").at(architecture == "x86" ? "eip" : "rip");
        // DbgHelp may append processor-state extensions beyond the base CONTEXT.
        harness::tests::check(inspected.at("exception").at("context_bytes").get<unsigned>() >= (architecture == "x86" ? 716u : 1232u) &&
            inspected.at("exception").at("program_counter") == expected_pc,
            "saved context matches captured registers: bytes=" + harness::dump_json(inspected.at("exception").at("context_bytes")) +
            " saved=" + harness::dump_json(inspected.at("exception").at("program_counter")) + " expected=" + harness::dump_json(expected_pc));
        auto replayed = execute("crash_replay", {{"manifest", harness::path_text(evidence(result, crash.at("reproducer")))}});
        harness::tests::check(replayed.at("reproduced") == true, "debugger-generated replay manifest");
        auto repeated = run({{"arguments", {"crash"}}, {"entry_breakpoint", false}, {"dump_on_crash", false}});
        harness::tests::check(repeated.at("crashes").front().at("signature") == crash.at("signature"), "stable module-relative crash signature");
        harness::tests::check(!store.records(session, "crash").empty(), "crash catalog persisted");
    });
    test("exported replay works after the original directory moves", [&] {
        const auto original = root / L"original-target", relocated = root / L"relocated-target";
        std::filesystem::create_directories(original);
        const auto original_executable = original / fixture.filename(); std::filesystem::copy_file(fixture, original_executable);
        const auto id = runtime.create_session(original_executable);
        auto collected = runtime.dispatch(id, "debug_run", {{"executable", harness::path_text(original_executable)}, {"arguments", {"crash"}}, {"entry_breakpoint", false}});
        harness::tests::check(collected.at("ok") == true && collected.at("crashes").size() == 1, "collect relocatable evidence");
        const auto destination = root / L"moved-export"; store.export_session(id, destination);
        harness::tests::check(original.is_absolute() && relocated.is_absolute() && original.parent_path() == root && relocated.parent_path() == root,
            "move is contained within the test workspace");
        std::filesystem::rename(original, relocated);
        const auto manifest = destination / harness::widen(collected.at("artifact_root")) / harness::widen(collected.at("crashes").front().at("reproducer"));
        auto replayed = runtime.dispatch(id, "crash_replay", {{"manifest", harness::path_text(manifest)},
            {"executable", harness::path_text(relocated / fixture.filename())}, {"working_directory", harness::path_text(relocated)}});
        harness::tests::check(replayed.at("ok") == true && replayed.at("reproduced") == true && !std::filesystem::exists(original),
            "replay uses preserved evidence and explicit overrides despite the stale session directory: " + harness::dump_json(replayed));
    });
    test("attachment detaches and live minidumps are not crash reports", [&] {
        harness::tests::c_process_fixture process(fixture);
        auto attached = execute("debug_attach", {{"pid", process.pid()}, {"monitor_ms", 150}});
        harness::tests::check(attached.at("ok") == true && attached.at("outcome") == "monitor_complete" && !attached.at("snapshots").empty(), "bounded attach: " + harness::dump_json(attached));
        harness::tests::check(WaitForSingleObject(process.handle(), 0) == WAIT_TIMEOUT, "attached target remains alive");
        auto snapshot = execute("dump_process", {{"pid", process.pid()}});
        harness::tests::check(snapshot.at("ok") == true && snapshot.at("kind") == "process_snapshot", "live process dump");
        auto info = execute("crash_info", {{"path", harness::path_text(evidence(snapshot, snapshot.at("minidump")))}});
        harness::tests::check(info.at("has_exception") == false, "live snapshot has no fabricated exception");
    });
    test("timeouts, cancellation, missing targets and descendant cleanup", [&] {
        auto timed = run({{"arguments", {"child"}}, {"timeout_ms", 250}, {"entry_breakpoint", false}});
        harness::tests::check(timed.at("ok") == false && timed.at("outcome") == "timeout", "debug timeout");
        auto child_pid = std::stoul(harness::research::read_binary(evidence(timed, timed.at("stdout")), 1024));
        harness::c_handle child(OpenProcess(SYNCHRONIZE, FALSE, child_pid));
        harness::tests::check(!child.valid() || WaitForSingleObject(child.get(), 2000) == WAIT_OBJECT_0, "debuggee descendants terminated");
        std::jthread trigger([&] { Sleep(200); cancelled.store(true); });
        auto interrupted = run({{"arguments", {"sleep"}}, {"entry_breakpoint", false}}); trigger.join();
        harness::tests::check(interrupted.at("ok") == false && interrupted.at("cancelled") == true, "cooperative research cancellation"); cancelled.store(false);
        auto failed = execute("debug_run", {{"executable", harness::path_text(root / L"missing.exe")}, {"arguments", harness::json_t::array()}});
        harness::tests::check(failed.at("ok") == false && failed.at("operation") == "Create debuggee", "worker errors leave harness running");
    });
    test("deterministic mutation campaigns, crash deduplication and replay", [&] {
        auto corpus = root / L"corpus"; std::filesystem::create_directories(corpus); harness::write_text(corpus / L"safe.bin", "safe");
        harness::json_t args = {{"executable", harness::path_text(fixture)}, {"arguments", {"input", "{input}"}}, {"corpus", harness::path_text(corpus)},
            {"iterations", 24}, {"random_seed", 123}, {"dictionary", {"CRASH"}}, {"case_timeout_ms", 1000}};
        auto first = execute("fuzz_run", args); auto second = execute("fuzz_run", args);
        harness::tests::check(first.at("ok") == true && second.at("ok") == true && first.at("iterations_completed") == 24 && first.at("crash_count").get<unsigned>() > 0, "mutation finds crashes: " + harness::dump_json(first));
        harness::tests::check(first.at("unique_crashes") == 1, "crashes deduplicated by signature");
        auto journal_a = harness::research::read_binary(evidence(first, "campaign.jsonl"), 1024 * 1024);
        auto journal_b = harness::research::read_binary(evidence(second, "campaign.jsonl"), 1024 * 1024);
        std::istringstream lines_a(journal_a), lines_b(journal_b); std::string line_a, line_b;
        while (std::getline(lines_a, line_a) && std::getline(lines_b, line_b)) {
            auto a = harness::json_t::parse(line_a), b = harness::json_t::parse(line_b);
            harness::tests::check(a.at("case").at("input_sha256") == b.at("case").at("input_sha256"), "deterministic case bytes");
        }
        auto reproducer = evidence(first, first.at("crashes").front().at("reproducer"));
        auto replayed = execute("crash_replay", {{"manifest", harness::path_text(reproducer)}});
        harness::tests::check(replayed.at("ok") == true && replayed.at("reproduced") == true, "verified reproducer replay: " + harness::dump_json(replayed));
        auto manifest = harness::read_json(reproducer); manifest["input_sha256"] = "wrong"; auto bad = reproducer.parent_path() / "tampered.json"; harness::write_text(bad, harness::dump_json(manifest));
        harness::tests::check(execute("crash_replay", {{"manifest", harness::path_text(bad)}}).at("ok") == false, "replay validates input hash");
    });
    test("stdin corpus, hangs, nonzero exits and input limits", [&] {
        auto corpus = root / L"stdin-corpus"; std::filesystem::create_directories(corpus);
        harness::write_text(corpus / L"a.bin", "CRASH"); harness::write_text(corpus / L"b.bin", "EXIT"); harness::write_text(corpus / L"c.bin", "HANG");
        auto result = execute("fuzz_run", {{"executable", harness::path_text(fixture)}, {"arguments", {"input", "-"}}, {"input_mode", "stdin"},
            {"corpus", harness::path_text(corpus)}, {"iterations", 3}, {"case_timeout_ms", 250}});
        harness::tests::check(result.at("ok") == true && result.at("crash_count") == 1 && result.at("timeouts") == 1 && result.at("nonzero_exits") == 1, "stdin outcomes: " + harness::dump_json(result));
        auto replayed = execute("crash_replay", {{"manifest", harness::path_text(evidence(result, result.at("crashes").front().at("reproducer")))}});
        harness::tests::check(replayed.at("reproduced") == true, "stdin replay");
        auto invalid = execute("fuzz_run", {{"executable", harness::path_text(fixture)}, {"arguments", {"input"}}, {"corpus", harness::path_text(corpus)}});
        harness::tests::check(invalid.at("ok") == false, "missing file placeholder rejected");
        auto limited = run({{"arguments", {"crash"}}, {"entry_breakpoint", false}, {"artifact_limit", 4096}});
        harness::tests::check(limited.at("ok") == false || limited.at("crashes").front().at("dump_result").at("ok") == false, "dump artifact limit is enforced");
    });
    test("binary evidence survives export and interrupted task recovery", [&] {
        auto destination = root / L"export"; store.export_session(session, destination);
        for (const auto& artifact : store.records(session, "artifact")) {
            const auto& data = artifact.at("data"); auto path = destination / harness::widen(data.at("path"));
            harness::tests::check(harness::sha256(path) == data.at("sha256").get<std::string>(), "exported evidence integrity");
        }
        const auto recovery_root = root / L"recovery"; std::string id;
        {
            harness::storage::c_evidence_store interrupted(recovery_root); id = interrupted.create_session(fixture, harness::json_t::object());
            auto task = interrupted.append(id, "task", {{"state", "running"}, {"tool", "fuzz_run"}}); auto workspace = interrupted.task_workspace(id, task);
            harness::write_text(workspace / "input.bin", std::string("\0\xff", 2));
            harness::write_text(workspace / "crash.json", harness::dump_json({{"signature", "partial-fixture"}, {"exception_code", EXCEPTION_ACCESS_VIOLATION}}));
        }
        harness::storage::c_evidence_store recovered(recovery_root);
        harness::tests::check(recovered.records(id, "task").front().at("data").at("state") == "interrupted" && recovered.records(id, "crash").size() == 1 && recovered.records(id, "artifact").size() == 3, "interrupted evidence imported without rerunning target");
    });
    test("partial manifests survive recovery, export and repeated reopening", [&] {
        const auto location = root / L"partial-manifests"; std::string id, task;
        {
            harness::storage::c_evidence_store initial(location); id = initial.create_session(fixture, harness::json_t::object());
            task = initial.append(id, "task", {{"state", "running"}, {"tool", "debug_run"}});
            const auto workspace = initial.task_workspace(id, task);
            for (const auto* directory : {"partial", "incomplete", "valid"}) std::filesystem::create_directories(workspace / directory);
            harness::write_text(workspace / "input.bin", "preserved input");
            harness::write_text(workspace / "worker.json", "{");
            harness::write_text(workspace / "partial" / "crash.json", "{");
            harness::write_text(workspace / "incomplete" / "crash.json", "{}");
            harness::write_text(workspace / "valid" / "crash.json", harness::dump_json({{"signature", "valid-fixture"}, {"exception_code", EXCEPTION_ACCESS_VIOLATION}}));
        }
        {
            harness::storage::c_evidence_store recovered(location);
            const auto tasks = recovered.records(id, "task"); const auto& result = tasks.front().at("data").at("result");
            harness::tests::check(tasks.front().at("data").at("state") == "interrupted" && result.at("evidence_warnings").size() == 3,
                "partial metadata is reported without blocking recovery");
            harness::tests::check(recovered.records(id, "crash").size() == 1 && result.at("crashes").size() == 1 && result.at("evidence_file_count") == 5,
                "valid record and all raw files are preserved");
            const auto destination = root / L"partial-export"; recovered.export_session(id, destination);
            for (const auto& artifact : recovered.records(id, "artifact")) {
                const auto& data = artifact.at("data");
                harness::tests::check(harness::sha256(destination / harness::widen(data.at("path"))) == data.at("sha256").get<std::string>(), "partial evidence export integrity");
            }
        }
        harness::storage::c_evidence_store reopened(location);
        harness::tests::check(reopened.list_sessions().size() == 1 && reopened.records(id, "crash").size() == 1 && reopened.records(id, "artifact").size() == 6,
            "reopening does not retry execution or duplicate evidence");
    });
    test("recovery still waits for a live worker with matching identity", [&] {
        const auto location = root / L"live-worker";
        harness::tests::c_process_fixture process(fixture);
        {
            harness::storage::c_evidence_store initial(location); auto id = initial.create_session(fixture, harness::json_t::object());
            auto task = initial.append(id, "task", {{"state", "running"}, {"tool", "debug_run"}});
            harness::write_text(initial.task_workspace(id, task) / "worker.json", harness::dump_json({{"pid", process.pid()},
                {"creation_time", harness::windows::process_creation_time(process.handle())}}));
        }
        bool refused = false;
        try { harness::storage::c_evidence_store recovery(location); }
        catch (const std::exception& error) { refused = std::string(error.what()).find("Previous research worker is still exiting") != std::string::npos; }
        harness::tests::check(refused && WaitForSingleObject(process.handle(), 0) == WAIT_TIMEOUT, "active identity prevents evidence recovery without terminating the worker");
    });
    test("abrupt controller exit cleans workers and recovers partial evidence", [&] {
        const auto location = root / L"abrupt"; std::string id;
        { harness::storage::c_evidence_store initial(location); id = initial.create_session(fixture, harness::json_t::object()); }
        const auto pid_file = root / L"target.pid"; const auto parameters = root / L"abrupt.json";
        harness::write_text(parameters, harness::dump_json({{"executable", harness::path_text(fixture)},
            {"arguments", {"pidfile", harness::path_text(pid_file)}}, {"entry_breakpoint", false}, {"timeout_ms", 10000}}));
        const auto controller_path = std::filesystem::absolute(argv[0]).parent_path() / L"glAIpnir.exe";
        harness::tests::c_process_fixture controller(controller_path, {"--store", harness::path_text(location), "--json", "debug", "run", id, "@" + harness::path_text(parameters)});
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while ((!std::filesystem::exists(pid_file) || std::filesystem::file_size(pid_file) == 0) && std::chrono::steady_clock::now() < deadline) Sleep(20);
        harness::tests::check(std::filesystem::exists(pid_file) && std::filesystem::file_size(pid_file) != 0, "owned target started before controller exit");
        const auto pid = static_cast<DWORD>(std::stoul(harness::research::read_binary(pid_file, 64)));
        harness::c_handle target(OpenProcess(SYNCHRONIZE, FALSE, pid));
        TerminateProcess(controller.handle(), 1); WaitForSingleObject(controller.handle(), 2000);
        harness::tests::check(!target.valid() || WaitForSingleObject(target.get(), 3000) == WAIT_OBJECT_0, "owned target exits with controller job");
        harness::storage::c_evidence_store recovered(location);
        harness::tests::check(recovered.records(id, "task").size() == 1 && recovered.records(id, "task").front().at("data").at("state") == "interrupted" &&
            !recovered.records(id, "artifact").empty(), "partial files imported without repeating execution");
    });
    std::cout << "Failures: " << failures << '\n'; return failures ? 1 : 0;
}
