#pragma once

#include <chrono>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>

#include "glaipnir/platform/windows/c_unique_handle.hpp"
#include "platform/windows/detail/win_util.hpp"

#include <tlhelp32.h>

namespace glaipnir::platform::windows::detail {

inline constexpr std::uint64_t ticks_per_second = 10'000'000;

std::wstring job_name(std::string_view session_id);

std::chrono::milliseconds ticks_to_ms(LONGLONG ticks);

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

}
