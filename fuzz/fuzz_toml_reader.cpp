#include <cstddef>
#include <cstdint>
#include <string_view>

#include "glaipnir/policy/c_toml_reader.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	const std::string_view text{reinterpret_cast<const char*>(data), size};
	(void)glaipnir::policy::c_toml_reader::parse(text);
	return 0;
}
