#include "persistence/detail/checkpoint_file.hpp"

#include <format>
#include <fstream>
#include <random>
#include <sstream>

#include "glaipnir/core/path_util.hpp"
#include "glaipnir/policy/c_toml_reader.hpp"

std::string glaipnir::persistence::detail::scratch_name(std::string_view purpose) {
    std::random_device device;
    return std::format(".{}-{:08x}", purpose, device());
}

glaipnir::core::result_t<void> glaipnir::persistence::detail::write_meta(const std::filesystem::path& file,
                                                                       const checkpoint_meta_t& meta) {
    std::ofstream output(file, std::ios::binary | std::ios::trunc);
    output << std::format("label = \"{}\"\ncreated_at = \"{}\"\nkind = \"{}\"\nfiles = {}\nbytes = {}\n"
                          "skipped_links = {}\npolicy_digest = \"{}\"\n",
                          meta.snapshot.label, meta.snapshot.created_at, to_string(meta.kind), meta.snapshot.files,
                          meta.snapshot.bytes, meta.snapshot.skipped_links, meta.policy_digest);
    output.flush();
    if (!output) {
        return core::make_error(core::error_code::io_error, "cannot write " + core::to_display_string(file));
    }
    return core::ok();
}

glaipnir::core::result_t<glaipnir::persistence::checkpoint_meta_t>
glaipnir::persistence::detail::read_meta(const std::filesystem::path& file) {
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        return core::make_error(core::error_code::not_found, "missing " + core::to_display_string(file));
    }
    std::stringstream buffer;
    buffer << input.rdbuf();
    auto reader = policy::c_toml_reader::parse(buffer.str());
    if (!reader) {
        return core::make_error(core::error_code::integrity_error,
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
        return core::make_error(core::error_code::integrity_error, core::to_display_string(file) + ": missing label");
    }
    return meta;
}
