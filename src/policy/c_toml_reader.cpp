#include "glaipnir/policy/c_toml_reader.hpp"

#include "policy/detail/c_toml_parser.hpp"

glaipnir::core::result_t<glaipnir::policy::c_toml_reader> glaipnir::policy::c_toml_reader::parse(std::string_view text) {
    return detail::c_toml_parser{text}.run();
}
