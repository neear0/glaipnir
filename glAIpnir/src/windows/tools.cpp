#include "harness/windows/tools.hpp"
#include "harness/core/util.hpp"
#include "harness/windows/analysis.hpp"
#include "harness/research/backend.hpp"
#include <array>
#include <chrono>
#include <fstream>
#include <thread>
#include <set>

static harness::json_t schema(const harness::json_t& properties, const harness::json_t& required) {
    return {{"type", "object"}, {"properties", properties}, {"required", required}, {"additionalProperties", false}};
}
harness::json_t harness::windows::tool_definitions() {
    const json_t text = {{"type", "string"}}, integer = {{"type", "integer"}, {"minimum", 0}};
    json_t result = json_t::array();
    for (const auto* name : {"file_metadata", "file_sha256", "pe_headers"})
        result.push_back({{"name", name}, {"description", "Inspect a local target file using native Windows operations."},
            {"parameters", schema({{"path", text}}, {"path"})}});
    result.push_back({{"name", "file_read"}, {"description", "Read bounded file bytes as hex and UTF-8 text."},
        {"parameters", schema({{"path", text}, {"offset", integer}, {"length", integer}}, {"path"})}});
    result.push_back({{"name", "process_launch"}, {"description", "Launch an executable; capture output and exit status."},
        {"parameters", schema({{"executable", text}, {"arguments", {{"type", "array"}, {"items", text}}}, {"working_directory", text}}, {"executable", "arguments"})}});
    result.push_back({{"name", "shell_execute"}, {"description", "Execute a Windows shell command with bounded output and runtime."},
        {"parameters", schema({{"command", text}, {"shell", {{"type", "string"}, {"enum", {"powershell", "cmd"}}}}, {"working_directory", text}}, {"command"})}});
    for (const auto& definition : analysis_definitions()) result.push_back(definition);
    for (const auto& definition : research::tool_definitions()) result.push_back(definition);
    return result;
}
void harness::windows::validate_tool(const std::string& name, const harness::json_t& arguments) {
    for (const auto& definition : harness::windows::tool_definitions()) if (definition.at("name") == name) {
        harness::validate_arguments(arguments, definition.at("parameters"));
        if (arguments.contains("creation_time") && !arguments.contains("pid")) throw std::runtime_error("creation_time requires pid");
        if (arguments.contains("token_creation_time") && !arguments.contains("token_pid")) throw std::runtime_error("token_creation_time requires token_pid");
        if (arguments.contains("target")) {
            const auto& target = arguments.at("target"); const auto kind = target.at("kind").get<std::string>();
            const auto locator = kind == "file" ? "path" : kind == "process" ? "pid" : kind == "service" ? "name" : "key";
            if (!target.contains(locator)) throw std::runtime_error("Missing target locator: " + std::string(locator));
            for (const auto& [key, ignored] : target.items()) {
                (void)ignored;
                if (key != "kind" && key != locator && !(kind == "process" && key == "creation_time") && !(kind == "registry" && key == "view")) throw std::runtime_error("Argument does not apply to target kind: " + key);
            }
        }
        return;
    }
    throw std::runtime_error("Unknown tool: " + name);
}
static std::string hex_bytes(const std::string& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string text; text.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) { text += digits[byte >> 4]; text += digits[byte & 15]; }
    return text;
}
static std::filesystem::path resolve_path(const std::string& value, const std::filesystem::path& directory) {
    auto path = std::filesystem::path(harness::widen(value));
    return std::filesystem::absolute(path.is_absolute() ? path : directory / path).lexically_normal();
}
static std::string read_bytes(const std::filesystem::path& path, std::uint64_t offset, std::size_t length) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot read file");
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) throw std::runtime_error("Offset too large");
    stream.seekg(static_cast<std::streamoff>(offset));
    if (!stream) throw std::runtime_error("Cannot seek file");
    std::string bytes(length, '\0'); stream.read(bytes.data(), static_cast<std::streamsize>(length));
    if (stream.bad()) throw std::runtime_error("File read failed");
    bytes.resize(static_cast<std::size_t>(stream.gcount())); return bytes;
}
static std::uint32_t read_integer(const std::string& bytes, std::size_t offset, std::size_t count) {
    if (offset > bytes.size() || count > bytes.size() - offset) throw std::runtime_error("Truncated PE header");
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < count; ++index) value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + index])) << (8 * index);
    return value;
}
static harness::json_t pe_headers(const std::filesystem::path& path) {
    const auto bytes = read_bytes(path, 0, 1024 * 1024);
    if (read_integer(bytes, 0, 2) != 0x5a4d) throw std::runtime_error("Missing DOS signature");
    const auto offset = static_cast<std::size_t>(read_integer(bytes, 0x3c, 4));
    if (offset < 64 || read_integer(bytes, offset, 4) != 0x4550) throw std::runtime_error("Invalid PE signature or offset");
    const auto optional_size = read_integer(bytes, offset + 20, 2);
    const auto sections = read_integer(bytes, offset + 6, 2);
    const auto optional = offset + 24;
    const auto magic = read_integer(bytes, optional, 2);
    if ((magic != 0x10b && magic != 0x20b) || optional_size < (magic == 0x20b ? 112u : 96u)) throw std::runtime_error("Invalid optional PE header");
    if (optional > bytes.size() || optional_size > bytes.size() - optional || sections > (bytes.size() - optional - optional_size) / 40)
        throw std::runtime_error("Truncated PE section table");
    harness::json_t section_data = harness::json_t::array();
    for (std::size_t index = 0; index < sections; ++index) {
        auto start = optional + optional_size + index * 40;
        auto name = bytes.substr(start, 8); name.resize(name.find('\0') == std::string::npos ? 8 : name.find('\0'));
        section_data.push_back({{"name", name}, {"virtual_size", read_integer(bytes, start + 8, 4)},
            {"virtual_address", read_integer(bytes, start + 12, 4)}, {"raw_size", read_integer(bytes, start + 16, 4)}});
    }
    return {{"ok", true}, {"machine", read_integer(bytes, offset + 4, 2)}, {"section_count", sections},
        {"characteristics", read_integer(bytes, offset + 22, 2)}, {"pe32_plus", magic == 0x20b},
        {"entry_point", read_integer(bytes, optional + 16, 4)}, {"subsystem", read_integer(bytes, optional + 68, 2)},
        {"dll_characteristics", read_integer(bytes, optional + 70, 2)}, {"sections", section_data}};
}
static void drain(HANDLE pipe, std::string& bytes, std::size_t limit, bool& truncated) {
    std::array<char, 8192> buffer{};
    for (;;) {
        DWORD available{};
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) || available == 0) return;
        DWORD count{};
        if (!ReadFile(pipe, buffer.data(), (std::min)(available, static_cast<DWORD>(buffer.size())), &count, nullptr) || count == 0) return;
        auto keep = (std::min)(static_cast<std::size_t>(count), limit - bytes.size());
        bytes.append(buffer.data(), keep); if (keep < count) truncated = true;
        // Bound each drain pass so continuous output cannot starve cancellation checks.
        if (available > buffer.size()) return;
    }
}
static harness::json_t run_process(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
    const std::filesystem::path& directory, const harness::limits_t& limits, const std::atomic_bool& cancelled) {
    using harness::check_win;
    harness::c_handle job(CreateJobObjectW(nullptr, nullptr)); check_win(job.valid(), "CreateJobObject");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
    job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    check_win(SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits)) != FALSE, "SetInformationJobObject");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_out{}, write_out{}, read_err{}, write_err{};
    check_win(CreatePipe(&read_out, &write_out, &attributes, 0) != FALSE, "CreatePipe");
    harness::c_handle stdout_read(read_out), stdout_write(write_out);
    check_win(CreatePipe(&read_err, &write_err, &attributes, 0) != FALSE, "CreatePipe");
    harness::c_handle stderr_read(read_err), stderr_write(write_err);
    check_win(SetHandleInformation(read_out, HANDLE_FLAG_INHERIT, 0) != FALSE, "SetHandleInformation");
    check_win(SetHandleInformation(read_err, HANDLE_FLAG_INHERIT, 0) != FALSE, "SetHandleInformation");
    harness::c_handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING, 0, nullptr));
    check_win(input.valid(), "Open NUL");
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = write_out; startup.StartupInfo.hStdError = write_err; startup.StartupInfo.hStdInput = input.get();
    SIZE_T attribute_size{}; InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
    std::vector<unsigned char> attribute_bytes(attribute_size);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_bytes.data());
    check_win(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_size) != FALSE, "InitializeProcThreadAttributeList");
    HANDLE handles[] = {write_out, write_err, input.get()};
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(startup.lpAttributeList); check_win(false, "UpdateProcThreadAttribute");
    }
    std::wstring command = harness::quote_argument(executable.wstring());
    for (const auto& argument : arguments) { command += L' '; command += harness::quote_argument(harness::widen(argument)); }
    // cmd parses its own /c command string rather than CRT argument escaping.
    if (executable.filename() == L"cmd.exe" && arguments.size() == 4)
        command = harness::quote_argument(executable.wstring()) + L" /d /s /c \"" + harness::widen(arguments.back()) + L"\"";
    PROCESS_INFORMATION process{};
    const BOOL launched = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, directory.c_str(), &startup.StartupInfo, &process);
    const DWORD launch_error = GetLastError(); DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (!launched) { SetLastError(launch_error); check_win(false, "CreateProcess"); }
    harness::c_handle process_handle(process.hProcess), thread_handle(process.hThread);
    if (!AssignProcessToJobObject(job.get(), process.hProcess)) { TerminateProcess(process.hProcess, 1); check_win(false, "AssignProcessToJobObject"); }
    if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) { TerminateJobObject(job.get(), 1); check_win(false, "ResumeThread"); }
    stdout_write = harness::c_handle(); stderr_write = harness::c_handle();
    std::string output, error; bool out_truncated = false, err_truncated = false, timed_out = false;
    const auto start = std::chrono::steady_clock::now();
    for (;;) {
        drain(read_out, output, limits.output_limit, out_truncated); drain(read_err, error, limits.output_limit, err_truncated);
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
        check_win(QueryInformationJobObject(job.get(), JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr) != FALSE, "QueryInformationJobObject");
        if (accounting.ActiveProcesses == 0) break;
        timed_out = std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(limits.operation_timeout_ms);
        if (cancelled.load() || timed_out) {
            check_win(TerminateJobObject(job.get(), 1) != FALSE, "TerminateJobObject"); WaitForSingleObject(process.hProcess, 5000); break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    // Once all writers have exited, capture remaining buffered bytes without blocking.
    for (int index = 0; index < 8; ++index) { drain(read_out, output, limits.output_limit, out_truncated); drain(read_err, error, limits.output_limit, err_truncated); }
    DWORD exit_code{}; check_win(GetExitCodeProcess(process.hProcess, &exit_code) != FALSE, "GetExitCodeProcess");
    return {{"ok", !timed_out && !cancelled.load() && exit_code == 0}, {"exit_code", exit_code}, {"timed_out", timed_out},
        {"cancelled", cancelled.load()}, {"stdout", output}, {"stderr", error}, {"stdout_hex", hex_bytes(output)}, {"stderr_hex", hex_bytes(error)},
        {"stdout_truncated", out_truncated}, {"stderr_truncated", err_truncated}, {"executable", harness::path_text(executable)},
        {"arguments", arguments}, {"working_directory", harness::path_text(directory)},
        {"elapsed_ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()}};
}
harness::json_t harness::windows::execute_tool(const std::string& name, const harness::json_t& arguments,
    const std::filesystem::path& default_directory, const harness::limits_t& limits, const std::atomic_bool& cancelled, const std::filesystem::path& workspace) {
    try {
        validate_tool(name, arguments);
        if (cancelled.load()) return {{"ok", false}, {"cancelled", true}};
        if (research::is_research_tool(name)) {
            const auto directory = arguments.contains("working_directory") && name != "crash_replay" ? resolve_path(arguments.at("working_directory"), default_directory) : default_directory;
            return research::execute(name, arguments, directory, limits, cancelled, workspace);
        }
        if (name.starts_with("service_") || name.starts_with("registry_") || name.starts_with("security_") || name == "token_info" ||
            name == "process_list" || name == "process_info" || name == "process_modules" || name == "process_threads") {
            auto result = execute_analysis(name, arguments, default_directory, limits, cancelled);
            if (dump_json(result).size() > limits.output_limit) throw c_windows_error("Analysis result exceeds output_limit", ERROR_INSUFFICIENT_BUFFER);
            return result;
        }
        const auto directory = arguments.contains("working_directory") ? resolve_path(arguments.at("working_directory"), default_directory) : default_directory;
        if (name == "shell_execute" || name == "process_launch") {
            if (name == "process_launch") return run_process(resolve_path(arguments.at("executable"), directory), arguments.at("arguments").get<std::vector<std::string>>(), directory, limits, cancelled);
            std::array<wchar_t, MAX_PATH> system{}; check_win(GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size())) != 0, "GetSystemDirectory");
            auto system_path = std::filesystem::path(system.data());
            if (arguments.value("shell", "powershell") == "cmd")
                return run_process(system_path / L"cmd.exe", {"/d", "/s", "/c", arguments.at("command")}, directory, limits, cancelled);
            return run_process(system_path / L"WindowsPowerShell/v1.0/powershell.exe", {"-NoProfile", "-NonInteractive", "-Command", arguments.at("command")}, directory, limits, cancelled);
        }
        const auto path = resolve_path(arguments.at("path"), default_directory);
        if (!std::filesystem::is_regular_file(path)) throw std::runtime_error("Path must identify a regular file");
        if (name == "file_metadata") {
            WIN32_FILE_ATTRIBUTE_DATA data{}; check_win(GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) != FALSE, "GetFileAttributesEx");
            ULARGE_INTEGER modified{}; modified.LowPart = data.ftLastWriteTime.dwLowDateTime; modified.HighPart = data.ftLastWriteTime.dwHighDateTime;
            return {{"ok", true}, {"path", path_text(path)}, {"size", std::filesystem::file_size(path)}, {"attributes", data.dwFileAttributes}, {"modified_filetime", modified.QuadPart}};
        }
        if (name == "file_sha256") return {{"ok", true}, {"path", path_text(path)}, {"sha256", sha256(path, &cancelled)}};
        if (name == "pe_headers") return pe_headers(path);
        const auto requested = arguments.value("length", std::uint64_t{4096});
        const auto length = static_cast<std::size_t>((std::min)(requested, static_cast<std::uint64_t>(limits.output_limit)));
        const auto offset = arguments.value("offset", std::uint64_t{0});
        auto bytes = read_bytes(path, offset, length);
        return {{"ok", true}, {"offset", offset}, {"bytes_read", bytes.size()}, {"text", bytes}, {"hex", hex_bytes(bytes)},
            {"truncated", requested > length || (offset < std::filesystem::file_size(path) && bytes.size() < std::filesystem::file_size(path) - offset)}};
    } catch (const c_windows_error& error) { auto result = error.result(); result["cancelled"] = cancelled.load(); return result; }
    catch (const std::exception& error) { return {{"ok", false}, {"error", error.what()}, {"cancelled", cancelled.load()}}; }
}
