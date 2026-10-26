#include "harness/research/backend.hpp"
#include "harness/research/dump_wire.hpp"
#include <DbgHelp.h>
#include <cstring>
#include <array>
#include <thread>

static harness::json_t dump_wow64(DWORD pid, const std::filesystem::path& path, std::uintmax_t limit, const std::function<bool()>& cancelled,
    DWORD tid, EXCEPTION_RECORD* exception, harness::research::thread_context_t* registers) {
    using harness::windows::require_win;
    harness::research::dump_request_t request; request.pid = pid; request.tid = tid;
    if (exception && registers) {
        request.has_exception = 1; request.exception_code = exception->ExceptionCode; request.exception_flags = exception->ExceptionFlags;
        request.exception_address = reinterpret_cast<std::uintptr_t>(exception->ExceptionAddress); request.parameter_count = (std::min)(exception->NumberParameters, DWORD{15});
        for (DWORD index = 0; index < request.parameter_count; ++index) request.parameters[index] = exception->ExceptionInformation[index];
        static_assert(sizeof(registers->wow64) == 716); std::memcpy(request.context.data(), &registers->wow64, sizeof(registers->wow64));
    }
    const auto request_path = std::filesystem::path(path.wstring() + L".request"), reply_path = std::filesystem::path(path.wstring() + L".reply");
    harness::write_text(request_path, std::string(reinterpret_cast<const char*>(&request), sizeof(request)));
    std::array<wchar_t, 32768> module{}; const auto size = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size())); require_win(size && size < module.size(), "Locate WOW64 dump helper");
    const auto executable = std::filesystem::path(std::wstring(module.data(), size)).parent_path() / L"glAIpnir-dump32.exe";
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE}; harness::c_handle event(CreateEventW(&attributes, TRUE, FALSE, nullptr)); require_win(event.valid(), "Create WOW64 dump cancellation");
    SIZE_T attribute_size{}; InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size); std::vector<unsigned char> data(attribute_size);
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(data.data());
    require_win(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_size), "Initialize WOW64 helper attributes"); HANDLE inherited[] = {event.get()};
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) { DeleteProcThreadAttributeList(startup.lpAttributeList); require_win(FALSE, "Set WOW64 helper handles"); }
    auto command = harness::quote_argument(executable.wstring()) + L" " + harness::quote_argument(request_path.wstring()) + L" " + harness::quote_argument(path.wstring()) + L" " +
        harness::quote_argument(reply_path.wstring()) + L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(event.get())) + L" " + std::to_wstring(limit);
    PROCESS_INFORMATION process{}; const auto launched = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &process);
    const auto error = GetLastError(); DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (!launched) throw harness::windows::c_windows_error("Launch WOW64 dump helper", error);
    harness::c_handle process_handle(process.hProcess), thread(process.hThread); const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (WaitForSingleObject(process.hProcess, 10) == WAIT_TIMEOUT) {
        if (cancelled()) SetEvent(event.get());
        if (std::chrono::steady_clock::now() >= deadline) { TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 2000); break; }
    }
    const auto bytes = harness::research::read_binary(reply_path, sizeof(harness::research::dump_reply_t));
    if (bytes.size() != sizeof(harness::research::dump_reply_t)) throw std::runtime_error("Invalid WOW64 dump reply");
    harness::research::dump_reply_t reply{}; std::memcpy(&reply, bytes.data(), bytes.size());
    if (reply.magic != request.magic) throw std::runtime_error("Invalid WOW64 dump reply magic");
    return {{"ok", reply.error == 0}, {"error_code", reply.error}, {"budget_exhausted", reply.budget_exhausted != 0}, {"cancelled", cancelled()}, {"kind", exception ? "exception_minidump" : "process_snapshot"}, {"architecture", "x86"}};
}

static BOOL CALLBACK dump_callback(PVOID parameter, const PMINIDUMP_CALLBACK_INPUT input, PMINIDUMP_CALLBACK_OUTPUT output) {
    auto& context = *static_cast<harness::research::dump_callback_t*>(parameter);
    if (input->CallbackType == CancelCallback) { output->CheckCancel = TRUE; output->Cancel = (*context.cancelled)(); }
    else if (input->CallbackType == IoStartCallback) output->Status = S_FALSE;
    else if (input->CallbackType == IoFinishCallback) output->Status = S_OK;
    else if (input->CallbackType == IoWriteAllCallback) {
        if ((*context.cancelled)() || input->Io.Offset > context.limit || input->Io.BufferBytes > context.limit - input->Io.Offset) {
            context.budget_exhausted = !(*context.cancelled)(); output->Status = E_ABORT; return TRUE;
        }
        LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(input->Io.Offset); DWORD count{};
        const BOOL written = SetFilePointerEx(context.file, position, nullptr, FILE_BEGIN) && WriteFile(context.file, input->Io.Buffer, input->Io.BufferBytes, &count, nullptr);
        output->Status = written && count == input->Io.BufferBytes ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    }
    return TRUE;
}
harness::json_t harness::research::write_dump(HANDLE process, DWORD pid, const std::filesystem::path& path, std::uintmax_t limit,
    const std::function<bool()>& cancelled, DWORD tid, EXCEPTION_RECORD* exception, harness::research::thread_context_t* registers) {
    USHORT machine{}, native{}; windows::require_win(IsWow64Process2(process, &machine, &native), "Query dump target architecture");
    if (machine == IMAGE_FILE_MACHINE_I386) return dump_wow64(pid, path, limit, cancelled, tid, exception, registers);
    c_handle file(CreateFileW(path.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    windows::require_win(file.valid(), "Create minidump");
    dump_callback_t callback{file.get(), limit, &cancelled, false}; MINIDUMP_CALLBACK_INFORMATION callbacks{dump_callback, &callback};
    EXCEPTION_POINTERS pointers{}; pointers.ExceptionRecord = exception;
    if (registers) pointers.ContextRecord = registers->is_wow64 ? reinterpret_cast<CONTEXT*>(&registers->wow64) : &registers->native;
    MINIDUMP_EXCEPTION_INFORMATION information{tid, &pointers, FALSE};
    const auto type = static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);
    BOOL success = MiniDumpWriteDump(process, pid, file.get(), type, exception && registers ? &information : nullptr, nullptr, &callbacks);
    const auto code = success ? ERROR_SUCCESS : GetLastError(); FlushFileBuffers(file.get());
    return {{"ok", success != FALSE}, {"error_code", code}, {"budget_exhausted", callback.budget_exhausted}, {"cancelled", cancelled()}, {"kind", exception ? "exception_minidump" : "process_snapshot"}};
}
harness::json_t harness::research::dump_process(const harness::json_t& args, harness::research::c_context& context) {
    json_t identity;
    auto process = windows::open_process(args, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    identity = {{"pid", args.at("pid")}, {"creation_time", windows::process_creation_time(process.get())}};
    auto result = write_dump(process.get(), args.at("pid"), context.path("snapshot.dmp"), context.remaining(), context.cancelled);
    result["identity"] = identity; result["minidump"] = "snapshot.dmp"; result["outcome"] = "snapshot";
    context.save("snapshot.json", dump_json(result, 2)); return result;
}
static void bounds(const std::string& bytes, std::uint64_t offset, std::uint64_t length) {
    if (offset > bytes.size() || length > bytes.size() - offset) throw std::runtime_error("Invalid or truncated minidump stream");
}
template<class c_type> static c_type read_at(const std::string& bytes, std::uint64_t offset) {
    bounds(bytes, offset, sizeof(c_type)); c_type value{}; std::memcpy(&value, bytes.data() + offset, sizeof(value)); return value;
}
harness::json_t harness::research::inspect_dump(const std::filesystem::path& path) {
    const auto bytes = read_binary(path, 256 * 1024 * 1024);
    const auto header = read_at<MINIDUMP_HEADER>(bytes, 0);
    if (header.Signature != MINIDUMP_SIGNATURE || (header.Version & 0xffff) != MINIDUMP_VERSION || header.NumberOfStreams > 4096) throw std::runtime_error("Invalid minidump header");
    bounds(bytes, header.StreamDirectoryRva, static_cast<std::uint64_t>(header.NumberOfStreams) * sizeof(MINIDUMP_DIRECTORY));
    json_t result = {{"ok", true}, {"size", bytes.size()}, {"sha256", data_hash(bytes)}, {"threads", json_t::array()}, {"modules", json_t::array()}, {"has_exception", false}};
    MINIDUMP_LOCATION_DESCRIPTOR exception_context{};
    for (ULONG index = 0; index < header.NumberOfStreams; ++index) {
        const auto stream = read_at<MINIDUMP_DIRECTORY>(bytes, header.StreamDirectoryRva + static_cast<std::uint64_t>(index) * sizeof(MINIDUMP_DIRECTORY));
        bounds(bytes, stream.Location.Rva, stream.Location.DataSize);
        if (stream.StreamType == SystemInfoStream) {
            if (stream.Location.DataSize < sizeof(MINIDUMP_SYSTEM_INFO)) throw std::runtime_error("Short system-info stream");
            const auto info = read_at<MINIDUMP_SYSTEM_INFO>(bytes, stream.Location.Rva);
            result["architecture"] = info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "other";
        } else if (stream.StreamType == ExceptionStream) {
            if (stream.Location.DataSize < sizeof(MINIDUMP_EXCEPTION_STREAM)) throw std::runtime_error("Short exception stream");
            auto exception = read_at<MINIDUMP_EXCEPTION_STREAM>(bytes, stream.Location.Rva); bounds(bytes, exception.ThreadContext.Rva, exception.ThreadContext.DataSize);
            exception_context = exception.ThreadContext;
            result["has_exception"] = true; result["exception"] = {{"thread_id", exception.ThreadId}, {"code", exception.ExceptionRecord.ExceptionCode},
                {"address", hex_address(exception.ExceptionRecord.ExceptionAddress)}, {"context_bytes", exception.ThreadContext.DataSize}};
        } else if (stream.StreamType == ThreadListStream || stream.StreamType == ModuleListStream) {
            if (stream.Location.DataSize < sizeof(ULONG)) throw std::runtime_error("Short minidump list");
            const auto count = read_at<ULONG>(bytes, stream.Location.Rva);
            const auto item_size = stream.StreamType == ThreadListStream ? sizeof(MINIDUMP_THREAD) : sizeof(MINIDUMP_MODULE);
            if (count > 4096 || static_cast<std::uint64_t>(count) * item_size + sizeof(ULONG) > stream.Location.DataSize) throw std::runtime_error("Invalid minidump list length");
            for (ULONG item = 0; item < count; ++item) {
                auto offset = stream.Location.Rva + sizeof(ULONG) + static_cast<std::uint64_t>(item) * item_size;
                if (stream.StreamType == ThreadListStream) {
                    const auto thread = read_at<MINIDUMP_THREAD>(bytes, offset); bounds(bytes, thread.ThreadContext.Rva, thread.ThreadContext.DataSize); bounds(bytes, thread.Stack.Memory.Rva, thread.Stack.Memory.DataSize);
                    result["threads"].push_back({{"tid", thread.ThreadId}, {"context_bytes", thread.ThreadContext.DataSize}, {"stack_bytes", thread.Stack.Memory.DataSize}});
                } else {
                    const auto module = read_at<MINIDUMP_MODULE>(bytes, offset); const auto length = read_at<ULONG>(bytes, module.ModuleNameRva);
                    if (length > 65536 || length % 2) throw std::runtime_error("Invalid minidump module name");
                    bounds(bytes, static_cast<std::uint64_t>(module.ModuleNameRva) + 4, length);
                    std::wstring name(length / 2, L'\0'); std::memcpy(name.data(), bytes.data() + module.ModuleNameRva + 4, length);
                    result["modules"].push_back({{"path", narrow(name)}, {"base_address", hex_address(module.BaseOfImage)}, {"size", module.SizeOfImage}});
                }
            }
        }
    }
    if (result.at("has_exception") == true && result.value("architecture", "") == "x86") {
        if (exception_context.DataSize < sizeof(WOW64_CONTEXT)) throw std::runtime_error("Short x86 exception context");
        const auto registers = read_at<WOW64_CONTEXT>(bytes, exception_context.Rva);
        result["exception"]["program_counter"] = hex_address(registers.Eip);
    } else if (result.at("has_exception") == true && result.value("architecture", "") == "x64") {
        if (exception_context.DataSize < sizeof(CONTEXT)) throw std::runtime_error("Short x64 exception context");
        const auto registers = read_at<CONTEXT>(bytes, exception_context.Rva);
        result["exception"]["program_counter"] = hex_address(registers.Rip);
    }
    return result;
}
