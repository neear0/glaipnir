#include "glaipnir/persistence/safe_fs.hpp"

#include <system_error>

#include "glaipnir/core/path_util.hpp"
#include "persistence/detail/fs_entry.hpp"
#include "persistence/detail/tree_walk.hpp"

glaipnir::core::result_t<glaipnir::persistence::tree_stats_t>
glaipnir::persistence::copy_tree(const std::filesystem::path& source, const std::filesystem::path& destination)
{
	std::error_code ec;
	if (detail::classify(source, ec) != detail::entry_kind::directory)
	{
		return core::make_error(core::error_code::invalid_argument,
		                        "copy source " + core::to_display_string(source) + " is not a plain directory");
	}
	if (std::filesystem::exists(std::filesystem::symlink_status(destination, ec)))
	{
		return core::make_error(core::error_code::already_exists,
		                        "copy destination " + core::to_display_string(destination) + " exists");
	}
	std::filesystem::create_directories(destination, ec);
	if (ec)
	{
		return detail::io_failure("cannot create", destination, ec);
	}
	tree_stats_t stats;
	auto copied = detail::copy_directory_contents(source, destination, stats);
	if (!copied)
	{
		return std::move(copied).error();
	}
	return stats;
}

glaipnir::core::result_t<void> glaipnir::persistence::remove_tree(const std::filesystem::path& root)
{
	std::error_code ec;
	if (!std::filesystem::exists(std::filesystem::symlink_status(root, ec)))
	{
		return core::ok();
	}
	const auto kind = detail::classify(root, ec);
	if (ec)
	{
		return detail::io_failure("cannot inspect", root, ec);
	}
	return kind == detail::entry_kind::directory ? detail::remove_directory_tree(root) : detail::remove_entry(root);
}

glaipnir::core::result_t<glaipnir::persistence::tree_stats_t> glaipnir::persistence::measure_tree(
	const std::filesystem::path& root)
{
	tree_stats_t stats;
	auto measured = detail::measure_directory(root, stats);
	if (!measured)
	{
		return std::move(measured).error();
	}
	return stats;
}
