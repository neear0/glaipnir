#include "platform/windows/detail/grant_plan.hpp"

#include <algorithm>

#include "glaipnir/core/path_util.hpp"
#include "glaipnir/platform/windows/path_acl.hpp"
#include "platform/windows/detail/c_sid.hpp"
#include "platform/windows/detail/mandatory_label.hpp"

std::vector<glaipnir::platform::windows::detail::ledger_entry_t>
glaipnir::platform::windows::detail::plan_grants(const grant_plan_input_t& input)
{
	std::vector<policy::path_rule_t> rules{{input.workspace, policy::access_mode::read_write}};
	if (input.restricted)
	{
		rules.push_back({input.container_folder, policy::access_mode::read_write});
	}
	rules.insert(rules.end(), input.rules.begin(), input.rules.end());

	const auto covered_by_rule = [&](const std::filesystem::path& path)
	{
		return std::any_of(rules.begin(), rules.end(), [&](const auto& rule)
		{
			return core::is_same_or_inside(path, rule.path);
		});
	};
	const auto is_exposed = [&](const std::filesystem::path& path)
	{
		return std::any_of(input.exposed.begin(), input.exposed.end(), [&](const auto& exposed)
		{
			return same_path(path, exposed);
		});
	};

	std::vector<ledger_entry_t> plan;
	const auto add = [&](ledger_entry_t entry)
	{
		if (std::none_of(plan.begin(), plan.end(), [&](const auto& existing) { return same_entry(existing, entry); }))
		{
			plan.push_back(std::move(entry));
		}
	};

	for (const auto& rule : rules)
	{
		const bool writable = rule.access == policy::access_mode::read_write;
		add({writable ? ledger_kind::read_write : ledger_kind::read_only, input.sid, rule.path});
		if (input.restricted && writable)
		{
			add({ledger_kind::low_label, std::string{no_sid}, rule.path});
		}
	}
	for (const auto& rule : rules)
	{
		for (auto ancestor = rule.path.parent_path();
		     ancestor.has_relative_path() && ancestor != ancestor.parent_path();
		     ancestor = ancestor.parent_path())
		{
			if (covered_by_rule(ancestor))
			{
				break;
			}
			if (!is_exposed(ancestor))
			{
				add({ledger_kind::traverse, input.sid, ancestor});
			}
		}
	}
	for (const auto& exposed : input.exposed)
	{
		if (!covered_by_rule(exposed))
		{
			add({ledger_kind::deny, input.sid, exposed});
		}
	}
	return plan;
}

glaipnir::core::result_t<void> glaipnir::platform::windows::detail::revert_entry(const ledger_entry_t& entry)
{
	if (entry.kind == ledger_kind::low_label)
	{
		return remove_label(entry.path);
	}
	auto sid = c_sid::from_string(entry.sid);
	if (!sid)
	{
		return std::move(sid).error();
	}
	return revoke_path_access(entry.path, sid->get());
}
