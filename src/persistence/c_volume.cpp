#include "glaipnir/persistence/c_volume.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <random>
#include <sstream>
#include <system_error>

#include "glaipnir/core/c_audit_log.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/core/validation.hpp"
#include "glaipnir/persistence/safe_fs.hpp"
#include "glaipnir/policy/c_toml_reader.hpp"

namespace glaipnir::persistence {

using core::error_code;
using core::make_error;
using core::result_t;

namespace fs = std::filesystem;

namespace {

constexpr std::string_view meta_file_name = "checkpoint.toml";

// Scratch names start with '.', which validate_identifier never allows, so they cannot
// collide with a real label and list_snapshots() can skip them.
std::string scratch_name(std::string_view purpose) {
    std::random_device device;
    return std::format(".{}-{:08x}", purpose, device());
}

result_t<void> write_meta(const fs::path& file, const checkpoint_meta_t& meta) {
    std::ofstream output(file, std::ios::binary | std::ios::trunc);
    output << std::format("label = \"{}\"\ncreated_at = \"{}\"\nkind = \"{}\"\nfiles = {}\nbytes = {}\n"
                          "skipped_links = {}\npolicy_digest = \"{}\"\n",
                          meta.snapshot.label, meta.snapshot.created_at, to_string(meta.kind), meta.snapshot.files,
                          meta.snapshot.bytes, meta.snapshot.skipped_links, meta.policy_digest);
    output.flush();
    if (!output) {
        return make_error(error_code::io_error, "cannot write " + core::to_display_string(file));
    }
    return core::ok();
}

result_t<checkpoint_meta_t> read_meta(const fs::path& file) {
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        return make_error(error_code::not_found, "missing " + core::to_display_string(file));
    }
    std::stringstream buffer;
    buffer << input.rdbuf();
    auto reader = policy::c_toml_reader::parse(buffer.str());
    if (!reader) {
        return make_error(error_code::integrity_error,
                          core::to_display_string(file) + ": " + reader.error().message);
    }
    const auto& entries = reader->entries();
    const auto text = [&](const char* key) -> std::string {
        const auto it = entries.find(key);
        const auto* value = it == entries.end() ? nullptr : std::get_if<std::string>(&it->second.data);
        return value == nullptr ? std::string{} : *value;
    };
    const auto number = [&](const char* key) -> std::uint64_t {
        const auto it = entries.find(key);
        const auto* value = it == entries.end() ? nullptr : std::get_if<std::int64_t>(&it->second.data);
        return value == nullptr || *value < 0 ? 0 : static_cast<std::uint64_t>(*value);
    };
    checkpoint_meta_t meta;
    meta.snapshot.label = text("label");
    meta.snapshot.created_at = text("created_at");
    meta.snapshot.files = number("files");
    meta.snapshot.bytes = number("bytes");
    meta.snapshot.skipped_links = number("skipped_links");
    meta.policy_digest = text("policy_digest");
    if (meta.snapshot.label.empty()) {
        return make_error(error_code::integrity_error, core::to_display_string(file) + ": missing label");
    }
    return meta;
}

} // namespace

std::string_view to_string(checkpoint_kind kind) noexcept {
    switch (kind) {
    case checkpoint_kind::filesystem: return "filesystem";
    case checkpoint_kind::process: return "process";
    case checkpoint_kind::machine: return "machine";
    }
    return "unknown";
}

result_t<c_volume> c_volume::open(fs::path root) {
    std::error_code ec;
    fs::create_directories(root / "workspace", ec);
    if (!ec) {
        fs::create_directories(root / "snapshots", ec);
    }
    if (ec) {
        return make_error(error_code::io_error, "cannot create volume at " + core::to_display_string(root) + ": " + ec.message(),
                          ec.value());
    }
    return c_volume{std::move(root)};
}

fs::path c_volume::snapshot_dir(std::string_view label) const {
    return root_ / "snapshots" / core::from_utf8(label);
}

result_t<checkpoint_meta_t> c_volume::snapshot(std::string_view label, std::string_view policy_digest) const {
    auto valid = core::validate_identifier(label, "snapshot label");
    if (!valid) {
        return std::move(valid).error();
    }
    const auto final_dir = snapshot_dir(label);
    std::error_code ec;
    if (fs::exists(fs::symlink_status(final_dir, ec))) {
        return make_error(error_code::already_exists, "snapshot '" + std::string{label} + "' already exists");
    }

    // Build under a scratch name and rename at the end so a crash never leaves a half-written
    // snapshot that looks complete.
    const auto scratch = root_ / "snapshots" / scratch_name("partial");
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
    auto written = write_meta(scratch / meta_file_name, meta);
    if (!written) {
        (void)remove_tree(scratch);
        return std::move(written).error();
    }
    fs::rename(scratch, final_dir, ec);
    if (ec) {
        (void)remove_tree(scratch);
        return make_error(error_code::io_error, "cannot finalize snapshot: " + ec.message(), ec.value());
    }
    return meta;
}

result_t<void> c_volume::rollback(std::string_view label) const {
    auto valid = core::validate_identifier(label, "snapshot label");
    if (!valid) {
        return valid;
    }
    const auto source = snapshot_dir(label) / "data";
    std::error_code ec;
    if (!fs::is_directory(source, ec)) {
        return make_error(error_code::not_found, "snapshot '" + std::string{label} + "' does not exist");
    }
    const auto incoming = root_ / scratch_name("incoming");
    auto copied = copy_tree(source, incoming);
    if (!copied) {
        (void)remove_tree(incoming);
        return std::move(copied).error();
    }
    const auto outgoing = root_ / scratch_name("outgoing");
    fs::rename(workspace(), outgoing, ec);
    if (ec) {
        (void)remove_tree(incoming);
        return make_error(error_code::io_error, "cannot move current workspace aside: " + ec.message(), ec.value());
    }
    fs::rename(incoming, workspace(), ec);
    if (ec) {
        std::error_code restore_ec;
        fs::rename(outgoing, workspace(), restore_ec);
        return make_error(error_code::io_error, "cannot install snapshot: " + ec.message(), ec.value());
    }
    // The old workspace is gone from the session's point of view; failing to delete it only
    // wastes disk, so it is not an error.
    (void)remove_tree(outgoing);
    return core::ok();
}

result_t<std::vector<checkpoint_meta_t>> c_volume::list_snapshots() const {
    std::vector<checkpoint_meta_t> snapshots;
    std::error_code ec;
    for (fs::directory_iterator it{root_ / "snapshots", ec}, end; !ec && it != end; it.increment(ec)) {
        const auto name = it->path().filename().u8string();
        if (name.empty() || name.front() == u8'.') {
            continue;
        }
        auto meta = read_meta(it->path() / meta_file_name);
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

result_t<void> c_volume::remove_snapshot(std::string_view label) const {
    auto valid = core::validate_identifier(label, "snapshot label");
    if (!valid) {
        return valid;
    }
    const auto dir = snapshot_dir(label);
    std::error_code ec;
    if (!fs::exists(fs::symlink_status(dir, ec))) {
        return make_error(error_code::not_found, "snapshot '" + std::string{label} + "' does not exist");
    }
    return remove_tree(dir);
}

result_t<c_volume> c_volume::clone_to(const fs::path& new_root) const {
    std::error_code ec;
    if (fs::exists(fs::symlink_status(new_root / "workspace", ec)) || fs::exists(fs::symlink_status(new_root / "snapshots", ec))) {
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

} // namespace glaipnir::persistence
