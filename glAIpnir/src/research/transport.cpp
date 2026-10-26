#include "harness/research/backend.hpp"
#include <array>
#include <thread>

harness::json_t harness::research::execute(const std::string& name, const harness::json_t& args, const std::filesystem::path& directory,
    const harness::limits_t& limits, const std::atomic_bool& cancelled, const std::filesystem::path& workspace) {
    using windows::require_win;
    if (workspace.empty()) throw std::runtime_error("Research tools require a session task workspace");
    std::filesystem::create_directories(workspace);
    std::array<wchar_t, 32768> module{}; DWORD length = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
    require_win(length && length < module.size(), "Locate research worker");
    auto worker = std::filesystem::path(std::wstring(module.data(), length)).parent_path() / L"glAIpnir-worker.exe";
    if (!std::filesystem::is_regular_file(worker)) throw std::runtime_error("glAIpnir-worker.exe must be installed beside the harness");
    const auto request_path = workspace / "request.json", response_path = workspace / "result.json";
    write_text(request_path, dump_json({{"tool", name}, {"arguments", args}, {"directory", path_text(directory)}, {"workspace", path_text(workspace)},
        {"configuration", {{"limits", {{"operation_timeout_ms", limits.operation_timeout_ms}, {"output_limit", limits.output_limit},
            {"http_timeout_ms", limits.http_timeout_ms}, {"max_turns", limits.max_turns}}}}}, {"version", HARNESS_VERSION}}));
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    c_handle cancel_event(CreateEventW(&attributes, TRUE, FALSE, nullptr)); require_win(cancel_event.valid(), "Create research cancellation event");
    c_handle log(CreateFileW((workspace / "worker.log").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)); require_win(log.valid(), "Open worker log");
    c_handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING, 0, nullptr)); require_win(input.valid(), "Open worker stdin");
    c_handle job(CreateJobObjectW(nullptr, nullptr)); require_win(job.valid(), "Create worker job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{}; job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    require_win(SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits)), "Configure worker job");
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.get(); startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = log.get();
    SIZE_T bytes{}; InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes); std::vector<unsigned char> buffer(bytes);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
    require_win(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes), "Initialize worker inheritance");
    HANDLE handles[] = {cancel_event.get(), log.get(), input.get()};
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(startup.lpAttributeList); require_win(FALSE, "Set worker inherited handles");
    }
    auto command = quote_argument(worker.wstring()) + L" " + quote_argument(request_path.wstring()) + L" " + quote_argument(response_path.wstring()) + L" " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(cancel_event.get()));
    PROCESS_INFORMATION process{};
    // Target paths use the directory in request.json; the worker only needs its existing workspace.
    BOOL launched = CreateProcessW(worker.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        nullptr, workspace.c_str(), &startup.StartupInfo, &process);
    const auto error = GetLastError(); DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (!launched) throw windows::c_windows_error("Launch research worker", error);
    c_handle process_handle(process.hProcess), thread_handle(process.hThread);
    if (!AssignProcessToJobObject(job.get(), process.hProcess)) { const auto code = GetLastError(); TerminateProcess(process.hProcess, 1); throw windows::c_windows_error("Assign research worker job", code); }
    write_text(workspace / "worker.json", dump_json({{"pid", process.dwProcessId}, {"creation_time", windows::process_creation_time(process.hProcess)}}));
    require_win(ResumeThread(process.hThread) != static_cast<DWORD>(-1), "Resume research worker");
    bool forced = false; auto cancelled_at = std::chrono::steady_clock::time_point{};
    while (WaitForSingleObject(process.hProcess, 20) == WAIT_TIMEOUT) {
        if (cancelled.load()) {
            SetEvent(cancel_event.get());
            if (cancelled_at == std::chrono::steady_clock::time_point{}) cancelled_at = std::chrono::steady_clock::now();
            if (std::chrono::steady_clock::now() - cancelled_at > std::chrono::seconds(5)) { TerminateJobObject(job.get(), 1); forced = true; WaitForSingleObject(process.hProcess, 5000); break; }
        }
    }
    DWORD status{}; require_win(GetExitCodeProcess(process.hProcess, &status), "Get research worker exit status");
    json_t result = std::filesystem::is_regular_file(response_path) ? json_t::parse(read_binary(response_path, 16 * 1024 * 1024)) : json_t{{"ok", false}, {"error", "Research worker exited without a result"}};
    result["worker_exit_code"] = status; result["worker_forced_stop"] = forced;
    if (status || forced) result["ok"] = false;
    return result;
}
