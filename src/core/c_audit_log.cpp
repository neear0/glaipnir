#include "glaipnir/core/c_audit_log.hpp"

#include <chrono>
#include <format>
#include <fstream>
#include <system_error>

#include "core/detail/audit_format.hpp"
#include "glaipnir/core/c_sha256.hpp"

std::string glaipnir::core::json_escape(std::string_view text)
{
	std::string escaped;
	escaped.reserve(text.size() + 8);
	for (const char c : text)
	{
		switch (c)
		{
		case '"': escaped += "\\\"";
			break;
		case '\\': escaped += "\\\\";
			break;
		case '\n': escaped += "\\n";
			break;
		case '\r': escaped += "\\r";
			break;
		case '\t': escaped += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(c) < 0x20)
			{
				escaped += std::format("\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(c)));
			}
			else
			{
				escaped += c;
			}
		}
	}
	return escaped;
}

std::string glaipnir::core::utc_timestamp()
{
	const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
	return std::format("{:%Y-%m-%dT%H:%M:%SZ}", now);
}

glaipnir::core::c_audit_log::c_audit_log(std::filesystem::path path, std::uint64_t sequence, std::string previous_hash)
	: path_(std::move(path)), sequence_(sequence), previous_hash_(std::move(previous_hash))
{
}

glaipnir::core::result_t<glaipnir::core::c_audit_log> glaipnir::core::c_audit_log::open(std::filesystem::path path)
{
	std::error_code ec;
	std::filesystem::create_directories(path.parent_path(), ec);
	if (ec)
	{
		return make_error(error_code::io_error, "cannot create audit directory: " + ec.message(), ec.value());
	}

	std::uint64_t sequence = 0;
	std::string previous{detail::genesis_hash};
	std::ifstream input(path, std::ios::binary);
	std::string line;
	std::string last_line;
	while (std::getline(input, line))
	{
		if (!line.empty())
		{
			last_line = line;
		}
	}
	if (!last_line.empty())
	{
		detail::parsed_record_t record;
		if (!detail::parse_record(last_line, record))
		{
			return make_error(error_code::integrity_error,
			                  "last record of audit log " + path.string() + " is malformed; refusing to extend it");
		}
		sequence = record.sequence;
		previous = record.hash;
	}
	return c_audit_log{std::move(path), sequence, std::move(previous)};
}

glaipnir::core::result_t<void> glaipnir::core::c_audit_log::record(std::string_view event, std::string_view detail)
{
	const std::uint64_t sequence = sequence_ + 1;
	std::string body = std::format("{{\"seq\":{},\"time\":\"{}\",\"event\":\"{}\",\"detail\":\"{}\",\"prev\":\"{}\"",
	                               sequence, utc_timestamp(), json_escape(event), json_escape(detail), previous_hash_);
	const std::string hash = c_sha256::hex_digest(body);
	std::string line = body;
	line += core::detail::hash_field;
	line += hash;
	line += "\"}\n";

	std::ofstream output(path_, std::ios::binary | std::ios::app);
	output << line;
	output.flush();
	if (!output)
	{
		return make_error(error_code::io_error, "cannot append to audit log " + path_.string());
	}
	sequence_ = sequence;
	previous_hash_ = hash;
	return ok();
}

glaipnir::core::result_t<std::uint64_t> glaipnir::core::c_audit_log::verify(const std::filesystem::path& path)
{
	std::ifstream input(path, std::ios::binary);
	if (!input)
	{
		return make_error(error_code::not_found, "audit log " + path.string() + " does not exist");
	}
	std::string expected_previous{detail::genesis_hash};
	std::uint64_t expected_sequence = 1;
	std::uint64_t line_number = 0;
	std::string line;
	while (std::getline(input, line))
	{
		++line_number;
		if (line.empty())
		{
			continue;
		}
		detail::parsed_record_t record;
		const auto where = " at line " + std::to_string(line_number);
		if (!detail::parse_record(line, record))
		{
			return make_error(error_code::integrity_error, "malformed record" + where);
		}
		if (record.sequence != expected_sequence)
		{
			return make_error(error_code::integrity_error, "sequence gap (expected " +
			                  std::to_string(expected_sequence) + ")" + where);
		}
		if (record.previous != expected_previous)
		{
			return make_error(error_code::integrity_error, "chain broken: prev hash mismatch" + where);
		}
		if (c_sha256::hex_digest(record.body) != record.hash)
		{
			return make_error(error_code::integrity_error, "record hash mismatch" + where);
		}
		expected_previous = record.hash;
		++expected_sequence;
	}
	return expected_sequence - 1;
}
