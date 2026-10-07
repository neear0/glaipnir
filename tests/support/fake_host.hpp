#pragma once

#include <string>
#include <string_view>

#include "glaipnir/policy/c_policy.hpp"
#include "support/test_harness.hpp"

namespace glaipnir::test
{
	struct fake_host_t
	{
		c_temp_dir temp;
		policy::host_context_t host;

		fake_host_t();

		std::string at(const char* relative) const;
	};

	bool policy_parses(std::string_view text, const policy::host_context_t& host);
}
