#include "detail/console.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

int __stdcall glaipnir::cli::detail::console_ctrl_handler(unsigned long type) noexcept
{
	return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ? TRUE : FALSE;
}

void glaipnir::cli::detail::ignore_interrupts(bool enable)
{
	SetConsoleCtrlHandler(console_ctrl_handler, enable ? TRUE : FALSE);
}
#else
void glaipnir::cli::detail::ignore_interrupts(bool)
{
}
#endif
