#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::core {

class c_audit_log {
public:
    static result_t<c_audit_log> open(std::filesystem::path path);

    result_t<void> record(std::string_view event, std::string_view detail);

    static result_t<std::uint64_t> verify(const std::filesystem::path& path);

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    c_audit_log(std::filesystem::path path, std::uint64_t sequence, std::string previous_hash);

    std::filesystem::path path_;
    std::uint64_t sequence_ = 0;
    std::string previous_hash_;
};

std::string json_escape(std::string_view text);

std::string utc_timestamp();

}
