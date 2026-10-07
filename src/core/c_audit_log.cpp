#include "glaipnir/core/c_audit_log.hpp"

#include <chrono>
#include <format>
#include <fstream>
#include <system_error>

#include "glaipnir/core/c_sha256.hpp"

namespace glaipnir::core {

namespace {

// The chain starts from a fixed all-zero hash so the first record is verifiable too.
const std::string genesis_hash(64, '0');
constexpr std::string_view hash_field = ",\"hash\":\"";
constexpr std::string_view prev_field = ",\"prev\":\"";
constexpr std::string_view seq_field = "{\"seq\":";

struct parsed_record_t {
    std::uint64_t sequence = 0;
    std::string body;       // everything the hash covers
    std::string previous;   // value of "prev"
    std::string hash;       // value of "hash"
};

// Records are produced only by record(), so a fixed-shape parse is sufficient and avoids
// pulling in a JSON library. Anything that does not match the shape counts as tampering.
bool parse_record(std::string_view line, parsed_record_t& out) {
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

} // namespace

std::string json_escape(std::string_view text) {
    std::string escaped;
    escaped.reserve(text.size() + 8);
    for (const char c : text) {
        switch (c) {
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                escaped += std::format("\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(c)));
            } else {
                escaped += c;
            }
        }
    }
    return escaped;
}

std::string utc_timestamp() {
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", now);
}

c_audit_log::c_audit_log(std::filesystem::path path, std::uint64_t sequence, std::string previous_hash)
    : path_(std::move(path)), sequence_(sequence), previous_hash_(std::move(previous_hash)) {}

result_t<c_audit_log> c_audit_log::open(std::filesystem::path path) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        return make_error(error_code::io_error, "cannot create audit directory: " + ec.message(), ec.value());
    }

    std::uint64_t sequence = 0;
    std::string previous = genesis_hash;
    std::ifstream input(path, std::ios::binary);
    std::string line;
    std::string last_line;
    while (std::getline(input, line)) {
        if (!line.empty()) {
            last_line = line;
        }
    }
    if (!last_line.empty()) {
        parsed_record_t record;
        if (!parse_record(last_line, record)) {
            return make_error(error_code::integrity_error,
                              "last record of audit log " + path.string() + " is malformed; refusing to extend it");
        }
        sequence = record.sequence;
        previous = record.hash;
    }
    return c_audit_log{std::move(path), sequence, std::move(previous)};
}

result_t<void> c_audit_log::record(std::string_view event, std::string_view detail) {
    const std::uint64_t sequence = sequence_ + 1;
    std::string body = std::format("{{\"seq\":{},\"time\":\"{}\",\"event\":\"{}\",\"detail\":\"{}\",\"prev\":\"{}\"",
                                   sequence, utc_timestamp(), json_escape(event), json_escape(detail), previous_hash_);
    const std::string hash = c_sha256::hex_digest(body);
    std::string line = body;
    line += hash_field;
    line += hash;
    line += "\"}\n";

    std::ofstream output(path_, std::ios::binary | std::ios::app);
    output << line;
    output.flush();
    if (!output) {
        return make_error(error_code::io_error, "cannot append to audit log " + path_.string());
    }
    sequence_ = sequence;
    previous_hash_ = hash;
    return ok();
}

result_t<std::uint64_t> c_audit_log::verify(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return make_error(error_code::not_found, "audit log " + path.string() + " does not exist");
    }
    std::string expected_previous = genesis_hash;
    std::uint64_t expected_sequence = 1;
    std::uint64_t line_number = 0;
    std::string line;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty()) {
            continue;
        }
        parsed_record_t record;
        const auto where = " at line " + std::to_string(line_number);
        if (!parse_record(line, record)) {
            return make_error(error_code::integrity_error, "malformed record" + where);
        }
        if (record.sequence != expected_sequence) {
            return make_error(error_code::integrity_error, "sequence gap (expected " +
                                                               std::to_string(expected_sequence) + ")" + where);
        }
        if (record.previous != expected_previous) {
            return make_error(error_code::integrity_error, "chain broken: prev hash mismatch" + where);
        }
        if (c_sha256::hex_digest(record.body) != record.hash) {
            return make_error(error_code::integrity_error, "record hash mismatch" + where);
        }
        expected_previous = record.hash;
        ++expected_sequence;
    }
    return expected_sequence - 1;
}

} // namespace glaipnir::core
