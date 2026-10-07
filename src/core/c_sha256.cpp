#include "glaipnir/core/c_sha256.hpp"

#include <cstring>

namespace glaipnir::core {

namespace {

constexpr std::array<std::uint32_t, 64> round_constants{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

constexpr std::uint32_t rotate_right(std::uint32_t value, int bits) noexcept {
    return (value >> bits) | (value << (32 - bits));
}

} // namespace

c_sha256::c_sha256() noexcept
    : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

void c_sha256::update(std::span<const std::uint8_t> data) noexcept {
    total_bytes_ += data.size();
    std::size_t offset = 0;
    if (buffer_size_ > 0) {
        const std::size_t take = std::min(data.size(), buffer_.size() - buffer_size_);
        std::memcpy(buffer_.data() + buffer_size_, data.data(), take);
        buffer_size_ += take;
        offset = take;
        if (buffer_size_ < buffer_.size()) {
            return;
        }
        process_block(buffer_.data());
        buffer_size_ = 0;
    }
    while (data.size() - offset >= 64) {
        process_block(data.data() + offset);
        offset += 64;
    }
    const std::size_t rest = data.size() - offset;
    std::memcpy(buffer_.data(), data.data() + offset, rest);
    buffer_size_ = rest;
}

void c_sha256::update(std::string_view text) noexcept {
    update(std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(text.data()), text.size()});
}

c_sha256::digest_type c_sha256::finish() noexcept {
    const std::uint64_t bit_length = total_bytes_ * 8;
    const std::uint8_t pad_start = 0x80;
    update(std::span<const std::uint8_t>{&pad_start, 1});
    const std::uint8_t zero = 0;
    while (buffer_size_ != 56) {
        update(std::span<const std::uint8_t>{&zero, 1});
    }
    std::array<std::uint8_t, 8> length_bytes{};
    for (int i = 0; i < 8; ++i) {
        length_bytes[7 - i] = static_cast<std::uint8_t>(bit_length >> (8 * i));
    }
    update(length_bytes);

    digest_type digest{};
    for (std::size_t i = 0; i < state_.size(); ++i) {
        digest[i * 4 + 0] = static_cast<std::uint8_t>(state_[i] >> 24);
        digest[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
        digest[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
    }
    return digest;
}

std::string c_sha256::hex_digest(std::string_view text) {
    c_sha256 hasher;
    hasher.update(text);
    return to_hex(hasher.finish());
}

std::string c_sha256::to_hex(const digest_type& digest) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string hex;
    hex.reserve(digest.size() * 2);
    for (const auto byte : digest) {
        hex += digits[byte >> 4];
        hex += digits[byte & 0x0f];
    }
    return hex;
}

void c_sha256::process_block(const std::uint8_t* block) noexcept {
    std::array<std::uint32_t, 64> schedule{};
    for (int i = 0; i < 16; ++i) {
        schedule[i] = (std::uint32_t{block[i * 4]} << 24) | (std::uint32_t{block[i * 4 + 1]} << 16) |
                      (std::uint32_t{block[i * 4 + 2]} << 8) | std::uint32_t{block[i * 4 + 3]};
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotate_right(schedule[i - 15], 7) ^ rotate_right(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);
        const std::uint32_t s1 = rotate_right(schedule[i - 2], 17) ^ rotate_right(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    auto [a, b, c, d, e, f, g, h] = state_;
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        const std::uint32_t choice = (e & f) ^ (~e & g);
        const std::uint32_t temp1 = h + s1 + choice + round_constants[i] + schedule[i];
        const std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

} // namespace glaipnir::core
