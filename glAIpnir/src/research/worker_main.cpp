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
        result = harness::research::summarize_result(std::move(result), context);
        harness::write_text(argv[2], harness::dump_json(result)); return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
