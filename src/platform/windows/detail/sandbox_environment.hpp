#pragma once

#include <array>
#include <string>

#include "platform/windows/detail/win_util.hpp"

namespace glaipnir::platform::windows::detail {

struct case_insensitive_less_t {
    bool operator()(const std::wstring& a, const std::wstring& b) const noexcept;
};

std::wstring host_variable(const wchar_t* name);

inline constexpr std::array<const wchar_t*, 18> essential_variables{
    L"SystemRoot", L"windir", L"SystemDrive", L"ComSpec", L"PATHEXT", L"OS",
    L"NUMBER_OF_PROCESSORS", L"PROCESSOR_ARCHITECTURE", L"PROCESSOR_IDENTIFIER", L"PROCESSOR_LEVEL",
    L"PROCESSOR_REVISION", L"ProgramData", L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432",
    L"CommonProgramFiles", L"CommonProgramFiles(x86)", L"CommonProgramW6432",
};

}
