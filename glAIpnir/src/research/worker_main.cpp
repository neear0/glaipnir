#include "harness/research/backend.hpp"
#include <iostream>

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 2 && std::wstring(argv[1]) == L"--version") { std::cout << HARNESS_VERSION "\n"; return 0; }
    if (argc != 4) return 2;
    try {
        const auto request = harness::read_json(argv[1]);
        HANDLE cancellation = reinterpret_cast<HANDLE>(std::stoull(argv[3]));
        harness::research::c_context context;
        context.workspace = harness::widen(request.at("workspace")); context.directory = harness::widen(request.at("directory"));
        context.limits = harness::parse_limits(request.at("configuration"));
        const auto& args = request.at("arguments"); context.artifact_limit = args.value("artifact_limit", std::uintmax_t{64 * 1024 * 1024});
        context.cancelled = [cancellation] { return WaitForSingleObject(cancellation, 0) == WAIT_OBJECT_0; };
        harness::json_t result;
        try { result = harness::research::worker_execute(request.at("tool"), args, context); }
        catch (const harness::windows::c_windows_error& error) { result = error.result(); }
        catch (const std::exception& error) { result = {{"ok", false}, {"error", error.what()}}; }
        if (harness::dump_json(result).size() > context.limits.output_limit) {
            try { context.save("full_result.json", harness::dump_json(result, 2)); } catch (const std::exception&) {}
            result.erase("events"); result.erase("snapshots"); result["output_truncated"] = true; result["full_result"] = "full_result.json";
            if (result.contains("crashes")) for (auto& crash : result["crashes"]) crash.erase("snapshot");
            if (harness::dump_json(result).size() > context.limits.output_limit) {
                const auto count = result.value("crashes", harness::json_t::array()).size(); result.erase("crashes");
                result["crashes_truncated"] = true; result["crashes_in_full_result"] = count;
            }
        }
        harness::write_text(argv[2], harness::dump_json(result)); return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
