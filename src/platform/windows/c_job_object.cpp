#include "glaipnir/platform/windows/c_job_object.hpp"

#include "win_util.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <set>

namespace glaipnir::platform::windows {

using core::error_code;
using core::result_t;

namespace {

constexpr std::uint64_t ticks_per_second = 10'000'000; // FILETIME / job times are in 100 ns units

std::wstring job_name(std::string_view session_id) {
    return L"Local\\glaipnir.job." + to_wide(session_id);
}

std::chrono::milliseconds ticks_to_ms(LONGLONG ticks) {
    return std::chrono::milliseconds{ticks / 10'000};
}

// Applies `action` once to every thread of every process in `pids`.
template <typename action_type>
void for_each_thread(const std::set<DWORD>& pids, action_type action) {
    c_unique_handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
    if (!snapshot.valid()) {
        return;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL more = Thread32First(snapshot.get(), &entry); more; more = Thread32Next(snapshot.get(), &entry)) {
        if (pids.contains(entry.th32OwnerProcessID)) {
            c_unique_handle thread{OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID)};
            if (thread.valid()) {
                action(thread.get());
            }
        }
    }
}

} // namespace

result_t<c_job_object> c_job_object::create(std::string_view session_id, const policy::resource_limit_t& limits,
                                            const policy::capability_t& capabilities) {
    c_unique_handle job{CreateJobObjectW(nullptr, job_name(session_id).c_str())};
    if (!job.valid()) {
        return last_error("cannot create job object");
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return core::make_error(error_code::busy, "session '" + std::string{session_id} + "' already has a running sandbox");
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended{};
    auto& basic = extended.BasicLimitInformation;
    // KILL_ON_JOB_CLOSE ties the sandbox's lifetime to ours: if glaipnir dies, nothing it
    // started keeps running unsupervised. No BREAKAWAY flags, so children cannot leave.
    basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (limits.memory_bytes != 0) {
        basic.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        extended.JobMemoryLimit = static_cast<SIZE_T>(limits.memory_bytes);
    }
    const std::uint32_t process_limit = capabilities.child_processes ? limits.max_processes : 1;
    if (process_limit != 0) {
        basic.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        basic.ActiveProcessLimit = process_limit;
    }
    if (limits.cpu_timeout_seconds != 0) {
        basic.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        basic.PerJobUserTimeLimit.QuadPart = static_cast<LONGLONG>(limits.cpu_timeout_seconds * ticks_per_second);
    }
    if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &extended, sizeof(extended))) {
        return last_error("cannot set job limits");
    }

    if (limits.cpu_percent != 0 && limits.cpu_percent < 100) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION rate{};
        rate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        rate.CpuRate = limits.cpu_percent * 100; // units of 1/100 percent
        if (!SetInformationJobObject(job.get(), JobObjectCpuRateControlInformation, &rate, sizeof(rate))) {
            return last_error("cannot set job CPU rate");
        }
    }

    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                             JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
    if (!capabilities.desktop_ui) {
        // HANDLES stops the sandbox from sending messages to (or reading) windows it does not own.
        ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_GLOBALATOMS;
    }
    if (!capabilities.clipboard_read) {
        ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
    }
    if (!capabilities.clipboard_write) {
        ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    }
    if (!SetInformationJobObject(job.get(), JobObjectBasicUIRestrictions, &ui, sizeof(ui))) {
        return last_error("cannot set job UI restrictions");
    }
    return c_job_object{std::move(job)};
}

result_t<c_job_object> c_job_object::open(std::string_view session_id) {
    c_unique_handle job{OpenJobObjectW(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE, FALSE, job_name(session_id).c_str())};
    if (!job.valid()) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            return core::make_error(error_code::not_found, "session '" + std::string{session_id} + "' is not running");
        }
        return last_error("cannot open job of session '" + std::string{session_id} + "'");
    }
    return c_job_object{std::move(job)};
}

result_t<void> c_job_object::terminate(unsigned exit_code) const {
    if (!TerminateJobObject(handle_.get(), exit_code)) {
        return last_error("cannot terminate job");
    }
    return core::ok();
}

result_t<std::vector<std::uint32_t>> c_job_object::process_ids() const {
    std::vector<std::uint8_t> buffer(sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 64 * sizeof(ULONG_PTR));
    while (true) {
        auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buffer.data());
        if (QueryInformationJobObject(handle_.get(), JobObjectBasicProcessIdList, list, static_cast<DWORD>(buffer.size()),
                                      nullptr)) {
            std::vector<std::uint32_t> ids;
            for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i) {
                ids.push_back(static_cast<std::uint32_t>(list->ProcessIdList[i]));
            }
            return ids;
        }
        if (GetLastError() != ERROR_MORE_DATA || buffer.size() > (1u << 24)) {
            return last_error("cannot list job processes");
        }
        buffer.resize(buffer.size() * 2);
    }
}

result_t<void> c_job_object::suspend() const {
    // A process may spawn a child while we walk its threads, so repeat until a pass finds no
    // process we have not already frozen.
    std::set<DWORD> frozen;
    for (int pass = 0; pass < 8; ++pass) {
        auto ids = process_ids();
        if (!ids) {
            return std::move(ids).error();
        }
        std::set<DWORD> fresh;
        for (const auto id : *ids) {
            if (!frozen.contains(id)) {
                fresh.insert(id);
            }
        }
        if (fresh.empty()) {
            return core::ok();
        }
        for_each_thread(fresh, [](HANDLE thread) { SuspendThread(thread); });
        frozen.insert(fresh.begin(), fresh.end());
    }
    return core::make_error(error_code::busy, "job kept spawning processes while being suspended");
}

result_t<void> c_job_object::resume() const {
    auto ids = process_ids();
    if (!ids) {
        return std::move(ids).error();
    }
    const std::set<DWORD> pids(ids->begin(), ids->end());
    for_each_thread(pids, [](HANDLE thread) { ResumeThread(thread); });
    return core::ok();
}

result_t<job_usage_t> c_job_object::usage() const {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    if (!QueryInformationJobObject(handle_.get(), JobObjectBasicAccountingInformation, &accounting, sizeof(accounting),
                                   nullptr)) {
        return last_error("cannot query job accounting");
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended{};
    if (!QueryInformationJobObject(handle_.get(), JobObjectExtendedLimitInformation, &extended, sizeof(extended),
                                   nullptr)) {
        return last_error("cannot query job memory");
    }
    job_usage_t usage;
    usage.user_time = ticks_to_ms(accounting.TotalUserTime.QuadPart);
    usage.kernel_time = ticks_to_ms(accounting.TotalKernelTime.QuadPart);
    usage.peak_memory_bytes = extended.PeakJobMemoryUsed;
    usage.active_processes = accounting.ActiveProcesses;
    return usage;
}

} // namespace glaipnir::platform::windows
