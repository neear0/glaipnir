#include <cstddef>
#include <cstdint>
#include <string_view>

#include "glaipnir/policy/c_policy.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	static const glaipnir::policy::host_context_t host{
		"/nonexistent/glaipnir-fuzz/home",
		"/nonexistent/glaipnir-fuzz/cwd",
		"/nonexistent/glaipnir-fuzz/state",
	};
	const std::string_view text{reinterpret_cast<const char*>(data), size};
	auto policy = glaipnir::policy::c_policy::parse(text, host);
	if (!policy)
	{
		return 0;
	}
	auto reparsed = glaipnir::policy::c_policy::parse(policy->to_toml(), host);
	if (!reparsed || reparsed->digest() != policy->digest())
	{
		__builtin_trap();
	}
	return 0;
}
