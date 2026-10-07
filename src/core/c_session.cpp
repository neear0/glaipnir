#include "glaipnir/core/c_session.hpp"

#include <algorithm>
#include <system_error>

#include "core/detail/session_files.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/core/validation.hpp"
#include "glaipnir/persistence/safe_fs.hpp"

glaipnir::core::c_session::c_session(persistence::session_config_t config, persistence::c_volume volume,
                                     c_audit_log audit,
                                     platform::c_session_lock lock)
	: config_(std::move(config)), volume_(std::move(volume)), audit_(std::move(audit)), lock_(std::move(lock))
{
}

std::filesystem::path glaipnir::core::c_session::directory_for(const std::filesystem::path& state_root,
                                                               std::string_view session_id)
{
	return state_root / "sessions" / from_utf8(session_id);
}

std::filesystem::path glaipnir::core::c_session::audit_path_for(const std::filesystem::path& state_root,
                                                                std::string_view session_id)
{
	return state_root / "audit" / from_utf8(std::string{session_id} + ".log");
}

glaipnir::core::result_t<glaipnir::core::c_session>
glaipnir::core::c_session::open(const persistence::session_config_t& config, open_mode mode)
{
	auto valid = validate_identifier(config.session_id, "session id");
	if (!valid)
	{
		return std::move(valid).error();
	}
	const auto directory = directory_for(config.state_root, config.session_id);
	std::error_code ec;
	const bool exists = std::filesystem::exists(directory / detail::session_meta_file_name, ec);
	if (mode == open_mode::create && exists)
	{
		return make_error(error_code::already_exists, "session '" + config.session_id + "' already exists");
	}
	if (mode == open_mode::open_existing && !exists)
	{
		return make_error(error_code::not_found, "session '" + config.session_id + "' does not exist");
	}
	std::filesystem::create_directories(directory, ec);
	if (ec)
	{
		return make_error(error_code::io_error, "cannot create session directory: " + ec.message(), ec.value());
	}
	auto lock = platform::c_session_lock::acquire(directory / detail::lock_file_name);
	if (!lock)
	{
		return std::move(lock).error();
	}
	auto volume = persistence::c_volume::open(directory);
	if (!volume)
	{
		return std::move(volume).error();
	}
	auto audit = c_audit_log::open(audit_path_for(config.state_root, config.session_id));
	if (!audit)
	{
		return std::move(audit).error();
	}
	if (!exists)
	{
		auto written = detail::write_session_meta(directory);
		if (!written)
		{
			return std::move(written).error();
		}
		(void)audit->record("session.create", config.ephemeral ? "ephemeral" : "persistent");
	}
	return c_session{config, std::move(*volume), std::move(*audit), std::move(*lock)};
}

glaipnir::core::result_t<std::vector<std::string>> glaipnir::core::c_session::list(
	const std::filesystem::path& state_root)
{
	std::vector<std::string> ids;
	std::error_code ec;
	const auto root = state_root / "sessions";
	if (!std::filesystem::exists(root, ec))
	{
		return ids;
	}
	for (std::filesystem::directory_iterator it{root, ec}, end; !ec && it != end; it.increment(ec))
	{
		const auto name_u8 = it->path().filename().u8string();
		const std::string name{name_u8.begin(), name_u8.end()};
		if (validate_identifier(name, "session id") && std::filesystem::exists(
			it->path() / detail::session_meta_file_name))
		{
			ids.push_back(name);
		}
	}
	if (ec)
	{
		return make_error(error_code::io_error, "cannot list sessions: " + ec.message(), ec.value());
	}
	std::sort(ids.begin(), ids.end());
	return ids;
}

glaipnir::core::result_t<void> glaipnir::core::c_session::destroy(const std::filesystem::path& state_root,
                                                                  std::string_view session_id)
{
	auto valid = validate_identifier(session_id, "session id");
	if (!valid)
	{
		return valid;
	}
	const auto directory = directory_for(state_root, session_id);
	std::error_code ec;
	if (!std::filesystem::exists(directory, ec))
	{
		return make_error(error_code::not_found, "session '" + std::string{session_id} + "' does not exist");
	}
	{
		auto lock = platform::c_session_lock::acquire(directory / detail::lock_file_name);
		if (!lock)
		{
			return std::move(lock).error();
		}
		auto cleaned = platform::cleanup_session(session_id, directory);
		if (!cleaned)
		{
			return cleaned;
		}
		for (std::filesystem::directory_iterator it{directory, ec}, end; !ec && it != end; it.increment(ec))
		{
			if (it->path().filename() != detail::lock_file_name)
			{
				auto removed = persistence::remove_tree(it->path());
				if (!removed)
				{
					return removed;
				}
			}
		}
	}
	auto removed = persistence::remove_tree(directory);
	if (!removed)
	{
		return removed;
	}
	if (auto audit = c_audit_log::open(audit_path_for(state_root, session_id)))
	{
		(void)audit->record("session.destroy", "");
	}
	return ok();
}

glaipnir::core::result_t<glaipnir::persistence::checkpoint_meta_t>
glaipnir::core::c_session::snapshot(std::string_view label, std::string_view policy_digest)
{
	auto meta = volume_.snapshot(label, policy_digest);
	if (meta)
	{
		(void)audit_.record("snapshot.create", std::string{label} + " files=" + std::to_string(meta->snapshot.files) +
		                    " skipped_links=" + std::to_string(meta->snapshot.skipped_links));
	}
	return meta;
}

glaipnir::core::result_t<void> glaipnir::core::c_session::rollback(std::string_view label)
{
	auto rolled = volume_.rollback(label);
	if (rolled)
	{
		(void)audit_.record("snapshot.rollback", label);
	}
	return rolled;
}

glaipnir::core::result_t<void> glaipnir::core::c_session::remove_snapshot(std::string_view label)
{
	auto removed = volume_.remove_snapshot(label);
	if (removed)
	{
		(void)audit_.record("snapshot.delete", label);
	}
	return removed;
}

glaipnir::core::result_t<std::vector<glaipnir::persistence::checkpoint_meta_t>>
glaipnir::core::c_session::snapshots() const
{
	return volume_.list_snapshots();
}

glaipnir::core::result_t<glaipnir::core::c_session> glaipnir::core::c_session::fork_session(std::string_view new_id)
{
	persistence::session_config_t child_config{std::string{new_id}, config_.state_root, false};
	auto child = open(child_config, open_mode::create);
	if (!child)
	{
		return child;
	}
	const auto child_dir = child->directory();
	auto cleared = persistence::remove_tree(child_dir / "workspace");
	if (cleared)
	{
		cleared = persistence::remove_tree(child_dir / "snapshots");
	}
	if (!cleared)
	{
		return std::move(cleared).error();
	}
	auto cloned = volume_.clone_to(child_dir);
	if (!cloned)
	{
		return std::move(cloned).error();
	}
	(void)audit_.record("session.fork", "to " + std::string{new_id});
	(void)child->audit().record("session.fork", "from " + config_.session_id);
	return child;
}
