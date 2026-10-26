#include "harness/research/backend.hpp"
#include <DbgHelp.h>
#include <psapi.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <cstring>

std::uint64_t harness::research::thread_context_t::pc() const { return is_wow64 ? wow64.Eip : native.Rip; }
std::uint64_t harness::research::thread_context_t::sp() const { return is_wow64 ? wow64.Esp : native.Rsp; }
void harness::research::thread_context_t::set_pc(std::uint64_t address) { if (is_wow64) wow64.Eip = static_cast<DWORD>(address); else native.Rip = address; }
void harness::research::thread_context_t::set_step(bool enabled) {
    auto& flags = is_wow64 ? wow64.EFlags : native.EFlags; if (enabled) flags |= 0x100; else flags &= ~0x100UL;
}
harness::research::c_debugger::c_debugger(harness::research::c_context& context) : context_(context) {}
harness::research::c_debugger::~c_debugger() { cleanup(); }
static harness::c_handle duplicate(HANDLE handle) {
    HANDLE result{}; harness::windows::require_win(DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &result, 0, FALSE, DUPLICATE_SAME_ACCESS), "Duplicate debug event handle");
    return harness::c_handle(result);
}
harness::research::thread_context_t harness::research::c_debugger::get_context(DWORD tid) const {
    thread_context_t context; context.is_wow64 = wow64_;
    const auto found = threads_.find(tid); if (found == threads_.end()) throw std::runtime_error("Debug thread disappeared");
    if (wow64_) { context.wow64.ContextFlags = WOW64_CONTEXT_FULL; windows::require_win(Wow64GetThreadContext(found->second.get(), &context.wow64), "Wow64GetThreadContext"); }
    else { context.native.ContextFlags = CONTEXT_FULL; windows::require_win(GetThreadContext(found->second.get(), &context.native), "GetThreadContext"); }
    return context;
}
void harness::research::c_debugger::set_context(DWORD tid, harness::research::thread_context_t& context) const {
    if (wow64_) windows::require_win(Wow64SetThreadContext(threads_.at(tid).get(), &context.wow64), "Wow64SetThreadContext");
    else windows::require_win(SetThreadContext(threads_.at(tid).get(), &context.native), "SetThreadContext");
}
harness::json_t harness::research::c_debugger::locate(std::uint64_t address) const {
    auto found = modules_.upper_bound(address);
    if (found != modules_.begin()) {
        --found; const auto& module = found->second;
        if (address - module.base < module.size) return {{"module", path_text(std::filesystem::path(widen(module.path)).filename())}, {"path", module.path}, {"rva", address - module.base}, {"address", hex_address(address)}};
    }
    return {{"module", "unknown"}, {"rva", 0}, {"address", hex_address(address)}};
}
void harness::research::c_debugger::arm(std::uint64_t address) {
    if (breakpoints_.contains(address)) return;
    unsigned char original{}; SIZE_T count{};
    windows::require_win(ReadProcessMemory(process_.get(), reinterpret_cast<void*>(address), &original, 1, &count) && count == 1, "Read breakpoint instruction");
    if (original == 0xcc) throw std::runtime_error("Requested breakpoint already contains INT3");
    unsigned char trap = 0xcc;
    windows::require_win(WriteProcessMemory(process_.get(), reinterpret_cast<void*>(address), &trap, 1, &count) && count == 1, "Write software breakpoint");
    breakpoints_.emplace(address, breakpoint_t{address, original});
    windows::require_win(FlushInstructionCache(process_.get(), reinterpret_cast<void*>(address), 1), "Flush breakpoint instruction cache");
}
void harness::research::c_debugger::restore_breakpoints() noexcept {
    for (const auto& [address, breakpoint] : breakpoints_) { SIZE_T count{}; WriteProcessMemory(process_.get(), reinterpret_cast<void*>(address), &breakpoint.original, 1, &count); FlushInstructionCache(process_.get(), reinterpret_cast<void*>(address), 1); }
    breakpoints_.clear();
}
void harness::research::c_debugger::resume_threads() noexcept {
    for (auto tid : suspended_) { auto found = threads_.find(tid); if (found != threads_.end()) ResumeThread(found->second.get()); }
    suspended_.clear();
}
void harness::research::c_debugger::cleanup() noexcept {
    if (!process_.valid()) return;
    restore_breakpoints(); resume_threads();
    if (symbols_) { SymCleanup(process_.get()); symbols_ = false; }
    if (!attached_ && job_.valid()) TerminateJobObject(job_.get(), 0);
    if (pending_) { ContinueDebugEvent(event_.dwProcessId, event_.dwThreadId, pending_status_); pending_ = false; }
    if (debugging_) {
        if (attached_) DebugActiveProcessStop(pid_);
        else {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (std::chrono::steady_clock::now() < deadline) {
                DEBUG_EVENT event{};
                if (!WaitForDebugEventEx(&event, 20)) { if (WaitForSingleObject(process_.get(), 0) == WAIT_OBJECT_0) break; continue; }
                if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
                if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
            }
            DebugActiveProcessStop(pid_);
        }
        debugging_ = false;
    }
}
harness::json_t harness::research::c_debugger::snapshot(DWORD tid, const harness::json_t& args) {
    auto context = get_context(tid); json_t registers;
    if (wow64_) registers = {{"eip", hex_address(context.wow64.Eip)}, {"esp", hex_address(context.wow64.Esp)}, {"ebp", hex_address(context.wow64.Ebp)},
        {"eax", hex_address(context.wow64.Eax)}, {"ebx", hex_address(context.wow64.Ebx)}, {"ecx", hex_address(context.wow64.Ecx)},
        {"edx", hex_address(context.wow64.Edx)}, {"esi", hex_address(context.wow64.Esi)}, {"edi", hex_address(context.wow64.Edi)}, {"flags", context.wow64.EFlags}};
    else registers = {{"rip", hex_address(context.native.Rip)}, {"rsp", hex_address(context.native.Rsp)}, {"rbp", hex_address(context.native.Rbp)},
        {"rax", hex_address(context.native.Rax)}, {"rbx", hex_address(context.native.Rbx)}, {"rcx", hex_address(context.native.Rcx)}, {"rdx", hex_address(context.native.Rdx)},
        {"rsi", hex_address(context.native.Rsi)}, {"rdi", hex_address(context.native.Rdi)}, {"r8", hex_address(context.native.R8)}, {"r9", hex_address(context.native.R9)},
        {"r10", hex_address(context.native.R10)}, {"r11", hex_address(context.native.R11)}, {"r12", hex_address(context.native.R12)}, {"r13", hex_address(context.native.R13)},
        {"r14", hex_address(context.native.R14)}, {"r15", hex_address(context.native.R15)}, {"flags", context.native.EFlags}};
    json_t result = {{"tid", tid}, {"architecture", wow64_ ? "x86" : "x64"}, {"registers", registers}, {"instruction", locate(context.pc())}, {"stack", json_t::array()}};
    if (!symbols_) {
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS | SYMOPT_IGNORE_CVREC | SYMOPT_UNDNAME);
        symbols_ = SymInitializeW(process_.get(), context_.directory.c_str(), TRUE) != FALSE;
        if (!symbols_) result["stack_error"] = windows::c_windows_error("SymInitialize", GetLastError()).result();
    }
    result["stack"].push_back(locate(context.pc()));
    if (symbols_) {
        auto walking = context;
        STACKFRAME64 frame{}; frame.AddrPC = {context.pc(), 0, AddrModeFlat}; frame.AddrStack = {context.sp(), 0, AddrModeFlat};
        frame.AddrFrame = {wow64_ ? context.wow64.Ebp : context.native.Rbp, 0, AddrModeFlat};
        for (int index = 0; index < 31; ++index) {
            if (!StackWalk64(wow64_ ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64, process_.get(), threads_.at(tid).get(), &frame,
                wow64_ ? static_cast<void*>(&walking.wow64) : static_cast<void*>(&walking.native), nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr) || !frame.AddrPC.Offset) break;
            if (result["stack"].back().at("address") != hex_address(frame.AddrPC.Offset)) result["stack"].push_back(locate(frame.AddrPC.Offset));
        }
    }
    auto read = [&](std::uint64_t address, std::size_t length) {
        std::string data(length, '\0'); SIZE_T count{};
        BOOL success = ReadProcessMemory(process_.get(), reinterpret_cast<void*>(address), data.data(), data.size(), &count); data.resize(count);
        json_t memory = {{"address", hex_address(address)}, {"requested", length}, {"bytes_read", count}, {"hex", windows::bytes_hex(data.data(), data.size())}, {"complete", success != FALSE && count == length}};
        if (!success) memory["error_code"] = GetLastError(); return memory;
    };
    result["instruction_bytes"] = read(context.pc(), 32); result["stack_bytes"] = read(context.sp(), 256); result["memory"] = json_t::array();
    for (const auto& request : args.value("memory_reads", json_t::array())) result["memory"].push_back(read(request.at("address"), request.at("length")));
    return result;
}
static std::string image_path(HANDLE file, HANDLE process, bool main_image) {
    std::array<wchar_t, 32768> buffer{};
    if (file && file != INVALID_HANDLE_VALUE) {
        DWORD size = GetFinalPathNameByHandleW(file, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED);
        if (size && size < buffer.size()) return harness::narrow(std::wstring(buffer.data(), size));
    }
    DWORD size = static_cast<DWORD>(buffer.size());
    if (main_image && QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) return harness::narrow(std::wstring(buffer.data(), size));
    return "unknown";
}
static void drain_pipe(HANDLE pipe, std::string& output, std::size_t limit, bool& truncated) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        DWORD available{}, count{}; if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) || !available) return;
        std::array<char, 8192> bytes{}; if (!ReadFile(pipe, bytes.data(), (std::min)(available, static_cast<DWORD>(bytes.size())), &count, nullptr) || !count) return;
        auto keep = (std::min)(static_cast<std::size_t>(count), limit - output.size()); output.append(bytes.data(), keep); if (keep < count) truncated = true;
    }
}
harness::json_t harness::research::c_debugger::run(const harness::json_t& args, const std::filesystem::path& relative, bool attach,
    const std::set<std::string>& known_signatures) {
    using windows::require_win;
    attached_ = attach; const auto started = std::chrono::steady_clock::now();
    const int timeout = (std::min)(context_.limits.operation_timeout_ms, attach ? args.value("monitor_ms", 1000) : args.value("timeout_ms", 5000));
    const auto deadline = started + std::chrono::milliseconds(timeout);
    const auto requests = args.value("breakpoints", json_t::array());
    if (requests.size() > 32 || args.value("memory_reads", json_t::array()).size() > 16) throw std::runtime_error("Too many breakpoints or memory reads");
    std::vector<bool> armed(requests.size(), false); c_handle stdout_read, stdout_write, stderr_read, stderr_write, input;
    std::filesystem::path executable;
    std::string stdin_hash;
    json_t result = {{"ok", true}, {"outcome", "unknown"}, {"events", json_t::array()}, {"snapshots", json_t::array()}, {"crashes", json_t::array()}};
    if (attach) {
        process_ = windows::open_process(args, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ); pid_ = args.at("pid");
        require_win(DebugActiveProcess(pid_), "DebugActiveProcess"); debugging_ = true;
        require_win(DebugSetProcessKillOnExit(FALSE), "Keep attached process alive on debugger exit");
    } else {
        executable = resolve_path(args.at("executable"), context_.directory);
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE}; HANDLE out_read{}, out_write{}, err_read{}, err_write{};
        require_win(CreatePipe(&out_read, &out_write, &attributes, 0), "Create debug stdout"); stdout_read = c_handle(out_read); stdout_write = c_handle(out_write);
        require_win(CreatePipe(&err_read, &err_write, &attributes, 0), "Create debug stderr"); stderr_read = c_handle(err_read); stderr_write = c_handle(err_write);
        require_win(SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0), "Set debug stdout inheritance"); require_win(SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0), "Set debug stderr inheritance");
        auto stdin_path = std::filesystem::path(L"NUL");
        if (args.contains("stdin_file")) {
            auto bytes = read_binary(resolve_path(args.at("stdin_file"), context_.directory), 1024 * 1024);
            stdin_hash = data_hash(bytes); context_.save(relative / "stdin.bin", bytes); stdin_path = context_.path(relative / "stdin.bin");
        }
        input = c_handle(CreateFileW(stdin_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING, 0, nullptr)); require_win(input.valid(), "Open debug stdin");
        job_ = c_handle(CreateJobObjectW(nullptr, nullptr)); require_win(job_.valid(), "Create debuggee job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{}; job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        require_win(SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits)), "Configure debuggee job");
        STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input.get(); startup.StartupInfo.hStdOutput = out_write; startup.StartupInfo.hStdError = err_write;
        SIZE_T size{}; InitializeProcThreadAttributeList(nullptr, 1, 0, &size); std::vector<unsigned char> attributes_data(size);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes_data.data()); require_win(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size), "Initialize debuggee attributes");
        HANDLE handles[] = {input.get(), out_write, err_write};
        if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(startup.lpAttributeList); require_win(FALSE, "Set debuggee inherited handles");
        }
        auto command = quote_argument(executable.wstring());
        for (const auto& argument : args.at("arguments")) { command += L' '; command += quote_argument(widen(argument)); }
        PROCESS_INFORMATION process{};
        BOOL created = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, context_.directory.c_str(), &startup.StartupInfo, &process);
        const auto error = GetLastError(); DeleteProcThreadAttributeList(startup.lpAttributeList);
        if (!created) throw windows::c_windows_error("Create debuggee", error);
        process_ = c_handle(process.hProcess); c_handle main_thread(process.hThread); pid_ = process.dwProcessId; debugging_ = true;
        if (!AssignProcessToJobObject(job_.get(), process_.get())) { const auto status = GetLastError(); TerminateProcess(process_.get(), 1); throw windows::c_windows_error("Assign debuggee job", status); }
        require_win(DebugSetProcessKillOnExit(TRUE), "Configure debuggee crash cleanup"); require_win(ResumeThread(main_thread.get()) != static_cast<DWORD>(-1), "Resume debuggee");
        stdout_write = c_handle(); stderr_write = c_handle();
        result["executable"] = path_text(executable); result["executable_sha256"] = sha256(executable); result["arguments"] = args.at("arguments");
    }
    USHORT machine{}, native{}; require_win(IsWow64Process2(process_.get(), &machine, &native), "Query debuggee architecture");
    wow64_ = machine == IMAGE_FILE_MACHINE_I386;
    if ((!wow64_ && native != IMAGE_FILE_MACHINE_AMD64) || (machine && machine != IMAGE_FILE_MACHINE_I386)) throw std::runtime_error("Debugger supports native x64 and WOW64 x86 targets");
    result["pid"] = pid_; result["creation_time"] = windows::process_creation_time(process_.get()); result["architecture"] = wow64_ ? "x86" : "x64";
    std::string output, error_output; bool output_truncated = false, error_truncated = false; DWORD stepping_tid = 0; int steps_left = 0;
    bool initial_breakpoint = true; const auto max_events = args.value("max_events", 1024u); std::size_t event_count = 0;
    auto record = [&](json_t event) { ++event_count; if (result["events"].size() < max_events) result["events"].push_back(std::move(event)); else result["events_truncated"] = true; };
    auto capture = [&](const char* reason, DWORD tid) {
        if (result["snapshots"].size() >= 128) { result["snapshots_truncated"] = true; return; }
        try { auto value = snapshot(tid, args); value["reason"] = reason; result["snapshots"].push_back(std::move(value)); }
        catch (const windows::c_windows_error& error) { result["snapshots"].push_back({{"tid", tid}, {"reason", reason}, {"error", error.result()}}); }
    };
    while (true) {
        if (stdout_read.valid()) { drain_pipe(stdout_read.get(), output, context_.limits.output_limit, output_truncated); drain_pipe(stderr_read.get(), error_output, context_.limits.output_limit, error_truncated); }
        if (context_.cancelled()) { result["ok"] = false; result["outcome"] = "cancelled"; result["cancelled"] = true; break; }
        if (std::chrono::steady_clock::now() >= deadline) { result["outcome"] = attach ? "monitor_complete" : "timeout"; result["ok"] = attach; break; }
        if (!WaitForDebugEventEx(&event_, 20)) { if (GetLastError() == ERROR_SEM_TIMEOUT) continue; require_win(FALSE, "WaitForDebugEventEx"); }
        pending_ = true; pending_status_ = DBG_CONTINUE;
        record({{"event", event_.dwDebugEventCode}, {"tid", event_.dwThreadId}, {"elapsed_ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count()}});
        if (event_.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT || event_.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            const bool main_image = event_.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT;
            HANDLE file = main_image ? event_.u.CreateProcessInfo.hFile : event_.u.LoadDll.hFile;
            c_handle image(file); const auto base = reinterpret_cast<std::uintptr_t>(main_image ? event_.u.CreateProcessInfo.lpBaseOfImage : event_.u.LoadDll.lpBaseOfDll);
            if (main_image) threads_.emplace(event_.dwThreadId, duplicate(event_.u.CreateProcessInfo.hThread));
            MODULEINFO info{};
            if (!GetModuleInformation(process_.get(), reinterpret_cast<HMODULE>(base), &info, sizeof(info))) {
                IMAGE_DOS_HEADER dos{}; SIZE_T count{};
                if (ReadProcessMemory(process_.get(), reinterpret_cast<void*>(base), &dos, sizeof(dos), &count) && dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 1024 * 1024) {
                    DWORD image_size{};
                    const auto offset = static_cast<std::uint64_t>(dos.e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage);
                    if (ReadProcessMemory(process_.get(), reinterpret_cast<void*>(base + offset), &image_size, sizeof(image_size), &count)) info.SizeOfImage = image_size;
                }
            }
            modules_[base] = module_t{base, info.SizeOfImage, image_path(file, process_.get(), main_image)};
            const auto& module = modules_.at(base);
            if (!attach && main_image && args.value("entry_breakpoint", true)) arm(reinterpret_cast<std::uintptr_t>(event_.u.CreateProcessInfo.lpStartAddress));
            for (std::size_t index = 0; index < requests.size(); ++index) if (!armed[index]) {
                const auto desired = requests[index].value("module", ""); const auto filename = path_text(std::filesystem::path(widen(module.path)).filename());
                if ((desired.empty() && main_image) || (!desired.empty() && _wcsicmp(widen(desired).c_str(), widen(filename).c_str()) == 0)) {
                    const auto rva = requests[index].at("rva").get<std::uint64_t>();
                    if (module.size && rva >= module.size) throw std::runtime_error("Breakpoint RVA lies outside its module");
                    arm(base + rva); armed[index] = true;
                }
            }
        } else if (event_.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            threads_.emplace(event_.dwThreadId, duplicate(event_.u.CreateThread.hThread));
            if (stepping_tid && event_.dwThreadId != stepping_tid && SuspendThread(threads_.at(event_.dwThreadId).get()) != static_cast<DWORD>(-1)) suspended_.insert(event_.dwThreadId);
        } else if (event_.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) { threads_.erase(event_.dwThreadId); suspended_.erase(event_.dwThreadId); }
        else if (event_.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
            const auto base = reinterpret_cast<std::uintptr_t>(event_.u.UnloadDll.lpBaseOfDll); const auto found = modules_.find(base);
            if (found != modules_.end()) {
                for (auto iterator = breakpoints_.begin(); iterator != breakpoints_.end();) {
                    if (iterator->first >= base && iterator->first - base < found->second.size) iterator = breakpoints_.erase(iterator); else ++iterator;
                }
                modules_.erase(found);
            }
        } else if (event_.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT) {
            const auto& debug = event_.u.DebugString; const auto length = (std::min)(static_cast<std::size_t>(debug.nDebugStringLength), std::size_t{2048});
            std::string bytes(length * (debug.fUnicode ? 2 : 1), '\0'); SIZE_T read{};
            if (ReadProcessMemory(process_.get(), debug.lpDebugStringData, bytes.data(), bytes.size(), &read)) {
                bytes.resize(read); std::string text = bytes;
                if (debug.fUnicode) { std::wstring wide(read / 2, L'\0'); std::memcpy(wide.data(), bytes.data(), wide.size() * 2); text = narrow(wide); }
                record({{"debug_string", text}});
            }
        } else if (event_.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto& exception = event_.u.Exception; auto address = reinterpret_cast<std::uintptr_t>(exception.ExceptionRecord.ExceptionAddress); auto code = exception.ExceptionRecord.ExceptionCode;
            record({{"exception_code", code}, {"address", hex_address(address)}, {"first_chance", exception.dwFirstChance != 0}});
            const auto owned = breakpoints_.find(address);
            if ((code == EXCEPTION_BREAKPOINT || code == 0x4000001fUL) && owned != breakpoints_.end()) {
                SIZE_T count{}; require_win(WriteProcessMemory(process_.get(), reinterpret_cast<void*>(address), &owned->second.original, 1, &count), "Restore one-shot breakpoint");
                require_win(FlushInstructionCache(process_.get(), reinterpret_cast<void*>(address), 1), "Flush restored breakpoint"); breakpoints_.erase(owned);
                auto registers = get_context(event_.dwThreadId); registers.set_pc(address); registers.set_step(false); set_context(event_.dwThreadId, registers);
                capture("breakpoint", event_.dwThreadId); initial_breakpoint = false;
                steps_left = args.value("step_count", 0);
                if (steps_left) {
                    stepping_tid = event_.dwThreadId;
                    for (const auto& [tid, thread] : threads_) if (tid != stepping_tid && !suspended_.contains(tid)) {
                        require_win(SuspendThread(thread.get()) != static_cast<DWORD>(-1), "Suspend other thread while stepping"); suspended_.insert(tid);
                    }
                    registers.set_step(true); set_context(event_.dwThreadId, registers);
                } else if (args.value("stop_on_breakpoint", false)) { result["outcome"] = "breakpoint"; break; }
            } else if ((code == EXCEPTION_SINGLE_STEP || code == 0x4000001eUL) && event_.dwThreadId == stepping_tid) {
                capture("single_step", event_.dwThreadId); auto registers = get_context(event_.dwThreadId);
                if (--steps_left <= 0) { registers.set_step(false); stepping_tid = 0; resume_threads(); }
                else registers.set_step(true);
                set_context(event_.dwThreadId, registers);
                if (!steps_left && args.value("stop_on_breakpoint", false)) { result["outcome"] = "breakpoint"; break; }
            } else if ((code == EXCEPTION_BREAKPOINT || code == 0x4000001fUL) && initial_breakpoint) {
                initial_breakpoint = false;
                if (attach) {
                    for (const auto& [tid, thread] : threads_) { (void)thread; if (result["snapshots"].size() >= 16) break; capture("attach", tid); }
                }
            } else if (exception.dwFirstChance) pending_status_ = DBG_EXCEPTION_NOT_HANDLED;
            else {
                capture("unhandled_exception", event_.dwThreadId); auto registers = get_context(event_.dwThreadId); auto location = locate(address);
                json_t crash = {{"exception_code", code}, {"exception_flags", exception.ExceptionRecord.ExceptionFlags}, {"thread_id", event_.dwThreadId},
                    {"location", location}, {"parameters", json_t::array()}, {"snapshot", result["snapshots"].empty() ? json_t(nullptr) : result["snapshots"].back()}};
                for (DWORD index = 0; index < (std::min)(exception.ExceptionRecord.NumberParameters, static_cast<DWORD>(EXCEPTION_MAXIMUM_PARAMETERS)); ++index) crash["parameters"].push_back(exception.ExceptionRecord.ExceptionInformation[index]);
                auto signature_source = std::to_string(code) + ":" + location.at("module").get<std::string>() + ":" + std::to_string(location.at("rva").get<std::uint64_t>());
                if (location.at("module") == "unknown") signature_source += ":" + hex_address(address);
                if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) && exception.ExceptionRecord.NumberParameters) signature_source += ":" + std::to_string(exception.ExceptionRecord.ExceptionInformation[0]);
                crash["signature"] = data_hash(signature_source); crash["signature_basis"] = signature_source; crash["signature_normalized"] = location.at("module") != "unknown"; crash["verified_vulnerability"] = false;
                const auto manifest_path = relative / "crash.json"; crash["manifest"] = path_text(manifest_path);
                context_.save(manifest_path, dump_json(crash, 2));
                if (args.value("dump_on_crash", true) && !known_signatures.contains(crash.at("signature").get<std::string>())) {
                    const auto dump = relative / "crash.dmp"; crash["minidump"] = path_text(dump);
                    try { crash["dump_result"] = write_dump(process_.get(), pid_, context_.path(dump), context_.remaining(), context_.cancelled, event_.dwThreadId, &exception.ExceptionRecord, &registers); }
                    catch (const std::exception& error) { crash["dump_result"] = {{"ok", false}, {"error", error.what()}}; }
                }
                if (!attach) {
                    json_t reproducer = {{"format_version", 1}, {"executable", path_text(executable)}, {"executable_sha256", result.at("executable_sha256")},
                        {"arguments_template", args.at("arguments")}, {"working_directory", path_text(context_.directory)}, {"expected_signature", crash.at("signature")},
                        {"input_mode", stdin_hash.empty() ? "none" : "stdin"}, {"timeout_ms", timeout}};
                    if (!stdin_hash.empty()) { reproducer["input_file"] = "stdin.bin"; reproducer["input_sha256"] = stdin_hash; }
                    crash["reproducer"] = path_text(relative / "reproducer.json"); context_.save(relative / "reproducer.json", dump_json(reproducer, 2));
                }
                context_.save(manifest_path, dump_json(crash, 2)); result["crashes"].push_back(crash); result["outcome"] = "crash"; pending_status_ = DBG_EXCEPTION_NOT_HANDLED; break;
            }
        } else if (event_.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            result["outcome"] = "exit"; result["exit_code"] = event_.u.ExitProcess.dwExitCode;
            require_win(ContinueDebugEvent(event_.dwProcessId, event_.dwThreadId, DBG_CONTINUE), "Continue exit event"); pending_ = false; debugging_ = false; break;
        }
        require_win(ContinueDebugEvent(event_.dwProcessId, event_.dwThreadId, pending_status_), "ContinueDebugEvent"); pending_ = false;
    }
    cleanup();
    if (stdout_read.valid()) for (int index = 0; index < 8; ++index) { drain_pipe(stdout_read.get(), output, context_.limits.output_limit, output_truncated); drain_pipe(stderr_read.get(), error_output, context_.limits.output_limit, error_truncated); }
    result["event_count"] = event_count; result["attached"] = attach; result["detached"] = attach; result["stdout_truncated"] = output_truncated; result["stderr_truncated"] = error_truncated;
    result["elapsed_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    result["stdout"] = path_text(relative / "stdout.bin"); result["stderr"] = path_text(relative / "stderr.bin");
    context_.save(relative / "stdout.bin", output); context_.save(relative / "stderr.bin", error_output);
    for (std::size_t index = 0; index < armed.size(); ++index) if (!armed[index]) result["unresolved_breakpoints"].push_back(requests[index]);
    context_.save(relative / "debug.json", dump_json(result, 2)); return result;
}
