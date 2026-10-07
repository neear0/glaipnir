#include "support/source_scan.hpp"

#include <regex>

std::filesystem::path glaipnir::test::source_root() {
    return std::filesystem::path{__FILE__}.parent_path().parent_path().parent_path();
}

bool glaipnir::test::is_snake_case(const std::string& name) {
    static const std::regex pattern{"^[a-z][a-z0-9_]*$"};
    return std::regex_match(name, pattern);
}

std::string glaipnir::test::strip_comments_and_strings(const std::string& code) {
    std::string out;
    out.reserve(code.size());
    for (std::size_t i = 0; i < code.size(); ++i) {
        if (code.compare(i, 2, "//") == 0) {
            while (i < code.size() && code[i] != '\n') {
                ++i;
            }
            out += '\n';
        } else if (code.compare(i, 2, "/*") == 0) {
            const auto end = code.find("*/", i + 2);
            i = end == std::string::npos ? code.size() : end + 1;
        } else if (code.compare(i, 2, "R\"") == 0) {
            const auto open = code.find('(', i);
            const auto delimiter = ")" + code.substr(i + 2, open - i - 2) + "\"";
            const auto end = code.find(delimiter, open);
            i = end == std::string::npos ? code.size() : end + delimiter.size() - 1;
            out += "\"\"";
        } else if (code[i] == '"' || code[i] == '\'') {
            const char quote = code[i];
            for (++i; i < code.size() && code[i] != quote; ++i) {
                if (code[i] == '\\') {
                    ++i;
                }
            }
            out += "\"\"";
        } else {
            out += code[i];
        }
    }
    return out;
}
