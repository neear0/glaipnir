#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace glaipnir::core
{
	class c_sha256
	{
	public:
		using digest_type = std::array<std::uint8_t, 32>;

		c_sha256() noexcept;

		void update(std::span<const std::uint8_t> data) noexcept;
		void update(std::string_view text) noexcept;
		digest_type finish() noexcept;

		static std::string hex_digest(std::string_view text);
		static std::string to_hex(const digest_type& digest);

	private:
		void process_block(const std::uint8_t* block) noexcept;

		std::array<std::uint32_t, 8> state_{};
		std::array<std::uint8_t, 64> buffer_{};
		std::size_t buffer_size_ = 0;
		std::uint64_t total_bytes_ = 0;
	};
}
