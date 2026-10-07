#include "core/detail/audit_format.hpp"

bool glaipnir::core::detail::parse_record(std::string_view line, parsed_record_t& out) {
    const auto hash_pos = line.rfind(hash_field);
    if (!line.starts_with(seq_field) || hash_pos == std::string_view::npos || !line.ends_with("\"}")) {
        return false;
    }
    out.body = std::string{line.substr(0, hash_pos)};
    const auto hash_start = hash_pos + hash_field.size();
    out.hash = std::string{line.substr(hash_start, line.size() - 2 - hash_start)};

    const auto prev_pos = out.body.rfind(prev_field);
    if (prev_pos == std::string::npos || !out.body.ends_with('"')) {
        return false;
    }
    const auto prev_start = prev_pos + prev_field.size();
    out.previous = out.body.substr(prev_start, out.body.size() - 1 - prev_start);

    std::uint64_t sequence = 0;
    std::size_t index = seq_field.size();
    if (index >= line.size() || line[index] < '0' || line[index] > '9') {
        return false;
    }
    while (index < line.size() && line[index] >= '0' && line[index] <= '9') {
        sequence = sequence * 10 + static_cast<std::uint64_t>(line[index] - '0');
        ++index;
    }
    out.sequence = sequence;
    return out.hash.size() == 64 && out.previous.size() == 64;
}
