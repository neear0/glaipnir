#pragma once

// Private helpers shared by the Windows backend sources. Not part of the public API.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows {

/// UTF-8 → UTF-16 for Win32 W-APIs.
std::wstring to_wide(std::string_view text);

/// UTF-16 → UTF-8.
std::string from_wide(std::wstring_view text);

/// System message text for a Win32 error code.
std::string win32_message(DWORD code);

/// error_t for the calling thread's GetLastError(), prefixed with what failed.
core::error_t last_error(std::string_view what, core::error_code code = core::error_code::platform_error);

/// error_t for an explicit Win32 error / HRESULT code.
core::error_t win32_error(std::string_view what, DWORD code, core::error_code category = core::error_code::platform_error);

} // namespace glaipnir::platform::windows
