#pragma once

#include <filesystem>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/persistence/persistence_types.hpp"

namespace glaipnir::persistence
{
	class c_volume
	{
	public:
		static core::result_t<c_volume> open(std::filesystem::path root);

		std::filesystem::path workspace() const { return root_ / "workspace"; }
		const std::filesystem::path& root() const noexcept { return root_; }

		core::result_t<checkpoint_meta_t> snapshot(std::string_view label, std::string_view policy_digest) const;

		core::result_t<void> rollback(std::string_view label) const;

		core::result_t<std::vector<checkpoint_meta_t>> list_snapshots() const;

		core::result_t<void> remove_snapshot(std::string_view label) const;

		core::result_t<c_volume> clone_to(const std::filesystem::path& new_root) const;

	private:
		explicit c_volume(std::filesystem::path root) : root_(std::move(root))
		{
		}

		std::filesystem::path snapshot_dir(std::string_view label) const;

		std::filesystem::path root_;
	};
}
