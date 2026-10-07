#include "platform/windows/detail/job_support.hpp"

std::wstring glaipnir::platform::windows::detail::job_name(std::string_view session_id)
{
	return L"Local\\glaipnir.job." + to_wide(session_id);
}

std::chrono::milliseconds glaipnir::platform::windows::detail::ticks_to_ms(LONGLONG ticks)
{
	return std::chrono::milliseconds{ticks / 10'000};
}
