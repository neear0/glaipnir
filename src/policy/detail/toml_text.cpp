#include "policy/detail/toml_text.hpp"

std::string glaipnir::policy::detail::quote_toml_string(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    out += '"';
    return out;
}
