#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::core {

/// Append-only, hash-chained audit log (JSON lines).
///
/// Every record carries the SHA-256 of the previous record, so deleting, reordering or editing
/// a line breaks verification from that point on. The log lives outside every sandbox-visible
/// path; chaining only detects tampering by someone who can write the file, it cannot prevent it.
class c_audit_log {
public:
    /// Opens (creating if needed) the log at `path` and resumes the chain from its last record.
    static result_t<c_audit_log> open(std::filesystem::path path);

    /// Appends one record. `event` is a dotted name ("run.start"); `detail` is free text.
    result_t<void> record(std::string_view event, std::string_view detail);

    /// Re-hashes every record of the log at `path`.
    /// @return number of records verified, or integrity_error naming the first bad line.
    static result_t<std::uint64_t> verify(const std::filesystem::path& path);

    /// Location of the log file.
    const std::filesystem::path& path() const noexcept { return path_; }

private:
    c_audit_log(std::filesystem::path path, std::uint64_t sequence, std::string previous_hash);

    std::filesystem::path path_;
    std::uint64_t sequence_ = 0;
    std::string previous_hash_;
};

/// Escapes a string for embedding inside a JSON string literal.
std::string json_escape(std::string_view text);

/// Current UTC time as RFC 3339 ("2026-10-07T03:00:00Z").
std::string utc_timestamp();

} // namespace glaipnir::core
