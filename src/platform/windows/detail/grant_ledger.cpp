#include "platform/windows/detail/grant_ledger.hpp"

#include <array>
#include <fstream>
#include <optional>
#include <system_error>

#include "glaipnir/core/path_util.hpp"

std::string_view glaipnir::platform::windows::detail::to_string(ledger_kind kind) noexcept
{
	switch (kind)
	{
	case ledger_kind::read_only: return "ro";
	case ledger_kind::read_write: return "rw";
	case ledger_kind::traverse: return "tr";
	case ledger_kind::deny: return "dn";
	case ledger_kind::low_label: return "lw";
	}
	return "??";
}

std::vector<glaipnir::platform::windows::detail::ledger_entry_t>
glaipnir::platform::windows::detail::read_ledger(const std::filesystem::path& file, std::string_view legacy_sid)
{
	constexpr std::array kinds{
		ledger_kind::read_only, ledger_kind::read_write, ledger_kind::traverse, ledger_kind::deny,
		ledger_kind::low_label,
	};
	std::vector<ledger_entry_t> entries;
	std::ifstream input(file, std::ios::binary);
	std::string line;
	while (std::getline(input, line))
	{
		if (!line.empty() && line.back() == '\r')
		{
			line.pop_back();
		}
		const auto first_tab = line.find('\t');
		if (first_tab != 2)
		{
			continue;
		}
		std::optional<ledger_kind> kind;
		for (const auto candidate : kinds)
		{
			if (std::string_view{line}.substr(0, 2) == to_string(candidate))
			{
				kind = candidate;
			}
		}
		if (!kind)
		{
			continue;
		}
		const auto second_tab = line.find('\t', first_tab + 1);
		ledger_entry_t entry;
		entry.kind = *kind;
		if (second_tab == std::string::npos)
		{
			entry.sid = std::string{legacy_sid};
			entry.path = core::from_utf8(std::string_view{line}.substr(first_tab + 1));
		}
		else
		{
			entry.sid = line.substr(first_tab + 1, second_tab - first_tab - 1);
			entry.path = core::from_utf8(std::string_view{line}.substr(second_tab + 1));
		}
		entries.push_back(std::move(entry));
	}
	return entries;
}

glaipnir::core::result_t<void> glaipnir::platform::windows::detail::write_ledger(const std::filesystem::path& file,
	const std::vector<ledger_entry_t>& entries)
{
	const auto scratch = std::filesystem::path{file}.concat(".new");
	{
		std::ofstream output(scratch, std::ios::binary | std::ios::trunc);
		for (const auto& entry : entries)
		{
			const auto path_text = entry.path.u8string();
			output << to_string(entry.kind) << '\t' << (entry.sid.empty() ? "-" : entry.sid) << '\t'
				<< std::string{path_text.begin(), path_text.end()} << '\n';
		}
		output.flush();
		if (!output)
		{
			return core::make_error(core::error_code::io_error,
			                        "cannot write grant ledger " + core::to_display_string(scratch));
		}
	}
	std::error_code ec;
	std::filesystem::rename(scratch, file, ec);
	if (ec)
	{
		return core::make_error(core::error_code::io_error, "cannot replace grant ledger: " + ec.message(), ec.value());
	}
	return core::ok();
}

bool glaipnir::platform::windows::detail::same_path(const std::filesystem::path& a, const std::filesystem::path& b)
{
	return core::is_same_or_inside(a, b) && core::is_same_or_inside(b, a);
}

bool glaipnir::platform::windows::detail::same_entry(const ledger_entry_t& a, const ledger_entry_t& b)
{
	return a.kind == b.kind && a.sid == b.sid && same_path(a.path, b.path);
}
