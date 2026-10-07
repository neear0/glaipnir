#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/policy_types.hpp"
#include "platform/windows/detail/grant_ledger.hpp"

namespace glaipnir::platform::windows::detail
{
	inline constexpr std::string_view no_sid = "-";

	struct grant_plan_input_t
	{
		std::string sid;
		std::filesystem::path workspace;
		std::filesystem::path container_folder;
		std::vector<policy::path_rule_t> rules;
		std::vector<std::filesystem::path> exposed;
		bool restricted = false;
	};

	std::vector<ledger_entry_t> plan_grants(const grant_plan_input_t& input);

	core::result_t<void> revert_entry(const ledger_entry_t& entry);
}
