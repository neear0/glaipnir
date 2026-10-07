#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace glaipnir::persistence
{
	enum class checkpoint_kind
	{
		filesystem,
		process,
		machine,
	};

	struct snapshot_info_t
	{
		std::string label;
		std::string created_at;
		std::uint64_t files = 0;
		std::uint64_t bytes = 0;
		std::uint64_t skipped_links = 0;
	};

	struct checkpoint_meta_t
	{
		snapshot_info_t snapshot;
		checkpoint_kind kind = checkpoint_kind::filesystem;
		std::string policy_digest;
	};

	struct session_config_t
	{
		std::string session_id;
		std::filesystem::path state_root;
		bool ephemeral = false;
	};

	std::string_view to_string(checkpoint_kind kind) noexcept;
}
