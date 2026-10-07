#include "glaipnir/isolation/isolation_types.hpp"

std::string_view glaipnir::isolation::to_string(termination_reason reason) noexcept
{
	switch (reason)
	{
	case termination_reason::exited: return "exited";
	case termination_reason::wall_timeout: return "wall_timeout";
	case termination_reason::cpu_timeout: return "cpu_timeout";
	case termination_reason::terminated: return "terminated";
	}
	return "unknown";
}
