#pragma once
#include <array>
#include <cstdint>

namespace harness::research {
#pragma pack(push, 1)
struct dump_request_t {
    std::uint32_t magic = 0x33444c47;
    std::uint32_t pid = 0;
    std::uint32_t tid = 0;
    std::uint32_t exception_code = 0;
    std::uint32_t exception_flags = 0;
    std::uint64_t exception_address = 0;
    std::uint32_t parameter_count = 0;
    std::array<std::uint64_t, 15> parameters{};
    std::uint32_t has_exception = 0;
    std::array<unsigned char, 716> context{};
};
struct dump_reply_t {
    std::uint32_t magic = 0x33444c47;
    std::uint32_t error = 0;
    std::uint32_t budget_exhausted = 0;
};
#pragma pack(pop)
}
