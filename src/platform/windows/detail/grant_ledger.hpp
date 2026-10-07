#pragma once

#include <filesystem>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::platform::windows::detail
{
	inline constexpr std::string_view ledger_file_name = "grants.ledger";

	struct ledger_entry_t
	{
		std::filesystem::path path;
		policy::access_mode access = policy::access_mode::read_only;
	};

	std::vector<ledger_entry_t> read_ledger(const std::filesystem::path& file);

	core::result_t<void> write_ledger(const std::filesystem::path& file, const std::vector<ledger_entry_t>& entries);

	bool same_path(const std::filesystem::path& a, const std::filesystem::path& b);
}
