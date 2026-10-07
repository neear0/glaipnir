#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace glaipnir::core::detail
{
	inline constexpr std::string_view genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000";
	inline constexpr std::string_view hash_field = ",\"hash\":\"";
	inline constexpr std::string_view prev_field = ",\"prev\":\"";
	inline constexpr std::string_view seq_field = "{\"seq\":";

	struct parsed_record_t
	{
		std::uint64_t sequence = 0;
		std::string body;
		std::string previous;
		std::string hash;
	};

	bool parse_record(std::string_view line, parsed_record_t& out);
}
