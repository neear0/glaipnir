#include "glaipnir/persistence/c_volume.hpp"

#include <algorithm>
#include <system_error>

#include "glaipnir/core/c_audit_log.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/core/validation.hpp"
#include "glaipnir/persistence/safe_fs.hpp"
#include "persistence/detail/checkpoint_file.hpp"

using glaipnir::core::error_code;
using glaipnir::core::make_error;
using glaipnir::core::result_t;

std::string_view glaipnir::persistence::to_string(checkpoint_kind kind) noexcept {
    switch (kind) {
    case checkpoint_kind::filesystem: return "filesystem";
    case checkpoint_kind::process: return "process";
    case checkpoint_kind::machine: return "machine";
    }
    return "unknown";
}

result_t<glaipnir::persistence::c_volume> glaipnir::persistence::c_volume::open(std::filesystem::path root) {
    std::error_code ec;
    std::filesystem::create_directories(root / "workspace", ec);
    if (!ec) {
        std::filesystem::create_directories(root / "snapshots", ec);
    }
    if (ec) {
        return make_error(error_code::io_error, "cannot create volume at " + core::to_display_string(root) + ": " + ec.message(),
                          ec.value());
    }
    return c_volume{std::move(root)};
}

std::filesystem::path glaipnir::persistence::c_volume::snapshot_dir(std::string_view label) const {
    return root_ / "snapshots" / core::from_utf8(label);
}

result_t<glaipnir::persistence::checkpoint_meta_t> glaipnir::persistence::c_volume::snapshot(std::string_view label,
                                                                                           std::string_view policy_digest) const {
    auto valid = core::validate_identifier(label, "snapshot label");
    if (!valid) {
        return std::move(valid).error();
    }
    const auto final_dir = snapshot_dir(label);
    std::error_code ec;
    if (std::filesystem::exists(std::filesystem::symlink_status(final_dir, ec))) {
        return make_error(error_code::already_exists, "snapshot '" + std::string{label} + "' already exists");
    }

    const auto scratch = root_ / "snapshots" / detail::scratch_name("partial");
    auto stats = copy_tree(workspace(), scratch / "data");
    if (!stats) {
        (void)remove_tree(scratch);
        return std::move(stats).error();
    }
    checkpoint_meta_t meta;
    meta.snapshot.label = std::string{label};
    meta.snapshot.created_at = core::utc_timestamp();
    meta.snapshot.files = stats->files;
    meta.snapshot.bytes = stats->bytes;
    meta.snapshot.skipped_links = stats->skipped.size();
    meta.kind = checkpoint_kind::filesystem;
    meta.policy_digest = std::string{policy_digest};
    auto written = detail::write_meta(scratch / detail::meta_file_name, meta);
    if (!written) {
        (void)remove_tree(scratch);
        return std::move(written).error();
    }
    std::filesystem::rename(scratch, final_dir, ec);
    if (ec) {
        (void)remove_tree(scratch);
        return make_error(error_code::io_error, "cannot finalize snapshot: " + ec.message(), ec.value());
    }
    return meta;
}

result_t<void> glaipnir::persistence::c_volume::rollback(std::string_view label) const {
    auto valid = core::validate_identifier(label, "snapshot label");
    if (!valid) {
        return valid;
    }
    const auto source = snapshot_dir(label) / "data";
    std::error_code ec;
    if (!std::filesystem::is_directory(source, ec)) {
        return make_error(error_code::not_found, "snapshot '" + std::string{label} + "' does not exist");
    }
    const auto incoming = root_ / detail::scratch_name("incoming");
    auto copied = copy_tree(source, incoming);
    if (!copied) {
        (void)remove_tree(incoming);
        return std::move(copied).error();
    }
    const auto outgoing = root_ / detail::scratch_name("outgoing");
    std::filesystem::rename(workspace(), outgoing, ec);
    if (ec) {
        (void)remove_tree(incoming);
        return make_error(error_code::io_error, "cannot move current workspace aside: " + ec.message(), ec.value());
    }
    std::filesystem::rename(incoming, workspace(), ec);
    if (ec) {
        std::error_code restore_ec;
        std::filesystem::rename(outgoing, workspace(), restore_ec);
        return make_error(error_code::io_error, "cannot install snapshot: " + ec.message(), ec.value());
    }
    (void)remove_tree(outgoing);
    return core::ok();
}

result_t<std::vector<glaipnir::persistence::checkpoint_meta_t>> glaipnir::persistence::c_volume::list_snapshots() const {
    std::vector<checkpoint_meta_t> snapshots;
    std::error_code ec;
    for (std::filesystem::directory_iterator it{root_ / "snapshots", ec}, end; !ec && it != end; it.increment(ec)) {
        const auto name = it->path().filename().u8string();
        if (name.empty() || name.front() == u8'.') {
            continue;
        }
        auto meta = detail::read_meta(it->path() / detail::meta_file_name);
        if (!meta) {
            return std::move(meta).error();
        }
        snapshots.push_back(std::move(*meta));
    }
    if (ec) {
        return make_error(error_code::io_error, "cannot list snapshots: " + ec.message(), ec.value());
    }
    std::sort(snapshots.begin(), snapshots.end(), [](const auto& a, const auto& b) {
        return a.snapshot.created_at != b.snapshot.created_at ? a.snapshot.created_at < b.snapshot.created_at
                                                              : a.snapshot.label < b.snapshot.label;
    });
    return snapshots;
}

result_t<void> glaipnir::persistence::c_volume::remove_snapshot(std::string_view label) const {
    auto valid = core::validate_identifier(label, "snapshot label");
    if (!valid) {
        return valid;
    }
    const auto dir = snapshot_dir(label);
    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::symlink_status(dir, ec))) {
        return make_error(error_code::not_found, "snapshot '" + std::string{label} + "' does not exist");
    }
    return remove_tree(dir);
}

result_t<glaipnir::persistence::c_volume> glaipnir::persistence::c_volume::clone_to(const std::filesystem::path& new_root) const {
    std::error_code ec;
    if (std::filesystem::exists(std::filesystem::symlink_status(new_root / "workspace", ec)) ||
        std::filesystem::exists(std::filesystem::symlink_status(new_root / "snapshots", ec))) {
        return make_error(error_code::already_exists, core::to_display_string(new_root) + " already holds a volume");
    }
    auto workspace_copy = copy_tree(workspace(), new_root / "workspace");
    if (!workspace_copy) {
        (void)remove_tree(new_root / "workspace");
        return std::move(workspace_copy).error();
    }
    auto snapshots_copy = copy_tree(root_ / "snapshots", new_root / "snapshots");
    if (!snapshots_copy) {
        (void)remove_tree(new_root / "workspace");
        (void)remove_tree(new_root / "snapshots");
        return std::move(snapshots_copy).error();
    }
    return c_volume{new_root};
}
