#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows::detail
{
	inline constexpr std::string_view ledger_file_name = "grants.ledger";

	enum class ledger_kind
	{
		read_only,
		read_write,
		traverse,
		deny,
		low_label,
	};

	struct ledger_entry_t
	{
		ledger_kind kind = ledger_kind::read_only;
		std::string sid;
		std::filesystem::path path;
	};

	std::vector<ledger_entry_t> read_ledger(const std::filesystem::path& file, std::string_view legacy_sid);

	core::result_t<void> write_ledger(const std::filesystem::path& file, const std::vector<ledger_entry_t>& entries);

	bool same_path(const std::filesystem::path& a, const std::filesystem::path& b);

	bool same_entry(const ledger_entry_t& a, const ledger_entry_t& b);

	std::string_view to_string(ledger_kind kind) noexcept;
}
