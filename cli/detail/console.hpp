#pragma once

namespace glaipnir::cli::detail {

void ignore_interrupts(bool enable);

#ifdef _WIN32
int __stdcall console_ctrl_handler(unsigned long type) noexcept;
#endif

}
