#include "support/fake_host.hpp"

#include "glaipnir/core/path_util.hpp"

glaipnir::test::fake_host_t::fake_host_t()
{
	std::filesystem::create_directories(temp.path() / "home" / ".ssh");
	std::filesystem::create_directories(temp.path() / "home" / "code" / "project");
	std::filesystem::create_directories(temp.path() / "home" / "AppData" / "Roaming" / "Microsoft");
	std::filesystem::create_directories(temp.path() / "state");
	std::filesystem::create_directories(temp.path() / "tools");
	host.home = temp.path() / "home";
	host.cwd = temp.path() / "home" / "code" / "project";
	host.state_root = temp.path() / "state";
}

std::string glaipnir::test::fake_host_t::at(const char* relative) const
{
	return core::to_display_string(temp.path() / relative);
}

bool glaipnir::test::policy_parses(std::string_view text, const policy::host_context_t& host)
{
	return policy::c_policy::parse(text, host).has_value();
}
