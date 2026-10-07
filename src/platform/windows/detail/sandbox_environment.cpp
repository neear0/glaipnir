#include "platform/windows/detail/sandbox_environment.hpp"

bool glaipnir::platform::windows::detail::case_insensitive_less_t::operator()(const std::wstring& a,
                                                                            const std::wstring& b) const noexcept {
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) ==
           CSTR_LESS_THAN;
}

std::wstring glaipnir::platform::windows::detail::host_variable(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) {
        return {};
    }
    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    value.resize(written);
    return value;
}
