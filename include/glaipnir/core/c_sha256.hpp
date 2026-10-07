#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace glaipnir::core {

/// Portable SHA-256 used for the audit hash chain and policy digests.
///
/// Implemented in-tree so the audit format does not depend on a platform crypto provider and
/// produces identical digests on every OS.
class c_sha256 {
public:
    using digest_type = std::array<std::uint8_t, 32>;

    c_sha256() noexcept;

    /// Feeds more bytes into the hash.
    void update(std::span<const std::uint8_t> data) noexcept;
    /// Feeds the bytes of a string into the hash.
    void update(std::string_view text) noexcept;
    /// Completes the hash. The object must not be updated afterwards.
    digest_type finish() noexcept;

    /// One-shot lowercase hex digest of `text`.
    static std::string hex_digest(std::string_view text);
    /// Lowercase hex encoding of a digest.
    static std::string to_hex(const digest_type& digest);

private:
    void process_block(const std::uint8_t* block) noexcept;

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffer_size_ = 0;
    std::uint64_t total_bytes_ = 0;
};

} // namespace glaipnir::core
