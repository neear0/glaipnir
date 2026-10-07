#pragma once

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

namespace glaipnir::platform::windows::detail
{
	std::wstring to_wide(std::string_view text);

	std::string from_wide(std::wstring_view text);

	std::string win32_message(DWORD code);

	core::error_t last_error(std::string_view what, core::error_code code = core::error_code::platform_error);

	core::error_t win32_error(std::string_view what, DWORD code,
	                          core::error_code category = core::error_code::platform_error);
}
