#include "harness/windows/analysis.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <array>

std::string harness::windows::process_creation_time(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    require_win(GetProcessTimes(process, &created, &exited, &kernel, &user), "GetProcessTimes");
    if (exited.dwLowDateTime || exited.dwHighDateTime) throw c_windows_error("Process has exited", ERROR_INVALID_PARAMETER);
    ULARGE_INTEGER time{}; time.LowPart = created.dwLowDateTime; time.HighPart = created.dwHighDateTime;
    return std::to_string(time.QuadPart);
}
harness::c_handle harness::windows::open_process(const harness::json_t& args, DWORD rights) {
    const auto pid = args.at("pid").get<DWORD>();
    c_handle process(OpenProcess(rights | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    require_win(process.valid(), "OpenProcess");
    auto creation = process_creation_time(process.get());
    if (args.contains("creation_time") && args.at("creation_time").get<std::string>() != creation)
        throw c_windows_error("Process identity changed (PID reused)", ERROR_INVALID_PARAMETER);
    return process;
}
static std::vector<PROCESSENTRY32W> process_entries() {
    harness::c_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    harness::windows::require_win(snapshot.valid(), "CreateToolhelp32Snapshot");
    std::vector<PROCESSENTRY32W> entries; PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) {
        if (GetLastError() != ERROR_NO_MORE_FILES) harness::windows::require_win(FALSE, "Process32First");
    } else {
        do { entries.push_back(entry); } while (Process32NextW(snapshot.get(), &entry));
        if (GetLastError() != ERROR_NO_MORE_FILES) harness::windows::require_win(FALSE, "Process32Next");
    }
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) { return left.th32ProcessID < right.th32ProcessID; });
    return entries;
}
static harness::json_t process_details(const PROCESSENTRY32W& entry, const harness::json_t& identity) {
    harness::json_t result = {{"pid", entry.th32ProcessID}, {"parent_pid", entry.th32ParentProcessID},
        {"name", harness::narrow(entry.szExeFile)}, {"thread_count", entry.cntThreads}};
    harness::json_t errors = harness::json_t::array();
    try {
        auto process = harness::windows::open_process(identity, PROCESS_QUERY_LIMITED_INFORMATION);
        result["creation_time"] = harness::windows::process_creation_time(process.get());
        std::array<wchar_t, 32768> path{}; DWORD length = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &length)) result["path"] = harness::narrow(std::wstring(path.data(), length));
        else errors.push_back(harness::windows::c_windows_error("QueryFullProcessImageName", GetLastError()).result());
        USHORT machine{}, native{};
        if (IsWow64Process2(process.get(), &machine, &native)) {
            result["machine"] = machine; result["native_machine"] = native;
            const auto effective = machine ? machine : native;
            result["architecture"] = effective == IMAGE_FILE_MACHINE_I386 ? "x86" : effective == IMAGE_FILE_MACHINE_AMD64 ? "x64" :
                effective == IMAGE_FILE_MACHINE_ARM64 ? "arm64" : effective == IMAGE_FILE_MACHINE_ARMNT ? "arm32" : "unknown";
        } else errors.push_back(harness::windows::c_windows_error("IsWow64Process2", GetLastError()).result());
        DWORD session{};
        if (ProcessIdToSessionId(entry.th32ProcessID, &session)) result["session_id"] = session;
        else errors.push_back(harness::windows::c_windows_error("ProcessIdToSessionId", GetLastError()).result());
    } catch (const harness::windows::c_windows_error& error) { errors.push_back(error.result()); }
    if (!errors.empty()) result["errors"] = errors;
    return result;
}
harness::json_t harness::windows::process_analysis(const std::string& name, const harness::json_t& args,
    const harness::limits_t& limits, const std::atomic_bool& cancelled) {
    c_page page(args, limits);
    if (name == "process_list" || name == "process_info") {
        if (name == "process_info") { auto process = open_process(args, PROCESS_QUERY_LIMITED_INFORMATION); }
        const auto entries = process_entries(); std::size_t index = 0;
        for (const auto& entry : entries) {
            if (cancelled.load()) break;
            if (name == "process_info" && entry.th32ProcessID != args.at("pid")) continue;
            auto item = process_details(entry, name == "process_info" ? args : json_t{{"pid", entry.th32ProcessID}});
            if (name == "process_info") { item["ok"] = !item.contains("errors"); item["partial"] = item.contains("errors"); return item; }
            if (!page.add(std::move(item), index++)) break;
        }
        if (name == "process_info" && !cancelled.load()) throw c_windows_error("Process disappeared from snapshot", ERROR_NOT_FOUND);
        return page.finish(cancelled.load());
    }
    auto process = open_process(args, name == "process_modules" ? PROCESS_QUERY_INFORMATION | PROCESS_VM_READ : PROCESS_QUERY_LIMITED_INFORMATION);
    const auto creation_time = process_creation_time(process.get()); json_t errors = json_t::array();
    if (name == "process_threads") {
        c_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)); require_win(snapshot.valid(), "CreateToolhelp32Snapshot threads");
        THREADENTRY32 entry{}; entry.dwSize = sizeof(entry); std::vector<THREADENTRY32> threads;
        if (Thread32First(snapshot.get(), &entry)) {
            do { if (entry.th32OwnerProcessID == args.at("pid")) threads.push_back(entry); if (cancelled.load()) break; } while (Thread32Next(snapshot.get(), &entry));
            if (!cancelled.load() && GetLastError() != ERROR_NO_MORE_FILES) errors.push_back(c_windows_error("Thread32Next", GetLastError()).result());
        } else if (GetLastError() != ERROR_NO_MORE_FILES) require_win(FALSE, "Thread32First");
        std::sort(threads.begin(), threads.end(), [](const auto& left, const auto& right) { return left.th32ThreadID < right.th32ThreadID; });
        for (std::size_t index = 0; index < threads.size() && !cancelled.load(); ++index)
            if (!page.add({{"tid", threads[index].th32ThreadID}, {"pid", threads[index].th32OwnerProcessID}, {"base_priority", threads[index].tpBasePri}, {"delta_priority", threads[index].tpDeltaPri}}, index)) break;
    } else {
        std::vector<HMODULE> modules(256); DWORD needed{}; bool complete = false;
        for (int attempt = 0; attempt < 4 && !cancelled.load(); ++attempt) {
            require_win(EnumProcessModulesEx(process.get(), modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL), "EnumProcessModulesEx");
            if (needed <= modules.size() * sizeof(HMODULE)) { modules.resize(needed / sizeof(HMODULE)); complete = true; break; }
            if (needed > 65536 * sizeof(HMODULE)) throw c_windows_error("Module list exceeds collection limit", ERROR_INSUFFICIENT_BUFFER);
            modules.resize(needed / sizeof(HMODULE) + 64);
        }
        if (!complete && !cancelled.load()) throw c_windows_error("Module list changed repeatedly", ERROR_MORE_DATA);
        std::sort(modules.begin(), modules.end(), [](auto left, auto right) { return reinterpret_cast<std::uintptr_t>(left) < reinterpret_cast<std::uintptr_t>(right); });
        for (std::size_t index = 0; index < modules.size() && !cancelled.load(); ++index) {
            json_t item = {{"base_address", reinterpret_cast<std::uintptr_t>(modules[index])}}; json_t module_errors = json_t::array();
            std::array<wchar_t, 32768> path{};
            DWORD count = GetModuleFileNameExW(process.get(), modules[index], path.data(), static_cast<DWORD>(path.size()));
            if (count && count < path.size()) item["path"] = narrow(std::wstring(path.data(), count));
            else module_errors.push_back(c_windows_error("GetModuleFileNameEx", count ? ERROR_INSUFFICIENT_BUFFER : GetLastError()).result());
            MODULEINFO information{};
            if (GetModuleInformation(process.get(), modules[index], &information, sizeof(information))) item["size"] = information.SizeOfImage;
            else module_errors.push_back(c_windows_error("GetModuleInformation", GetLastError()).result());
            if (!module_errors.empty()) item["errors"] = module_errors;
            if (!page.add(std::move(item), index)) break;
        }
    }
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process.get(), &created, &exited, &kernel, &user)) errors.push_back(c_windows_error("GetProcessTimes after enumeration", GetLastError()).result());
    else if (exited.dwLowDateTime || exited.dwHighDateTime) errors.push_back(c_windows_error("Process exited during enumeration", ERROR_PROCESS_ABORTED).result());
    auto result = page.finish(cancelled.load()); result["pid"] = args.at("pid"); result["creation_time"] = creation_time;
    if (!errors.empty()) { result["errors"] = errors; result["partial"] = true; }
    return result;
}
