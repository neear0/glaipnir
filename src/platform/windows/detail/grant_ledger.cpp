#include "platform/windows/detail/grant_ledger.hpp"

#include <fstream>
#include <string>
#include <system_error>

#include "glaipnir/core/path_util.hpp"

std::vector<glaipnir::platform::windows::detail::ledger_entry_t>
glaipnir::platform::windows::detail::read_ledger(const std::filesystem::path& file)
{
	std::vector<ledger_entry_t> entries;
	std::ifstream input(file, std::ios::binary);
	std::string line;
	while (std::getline(input, line))
	{
		if (line.size() < 4 || line[2] != '\t')
		{
			continue;
		}
		entries.push_back({
			core::from_utf8(std::string_view{line}.substr(3)),
			line.starts_with("rw") ? policy::access_mode::read_write : policy::access_mode::read_only
		});
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
			output << (entry.access == policy::access_mode::read_write ? "rw" : "ro") << '\t'
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
