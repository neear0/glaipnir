#include "test_harness.hpp"

#include <regex>

// Enforces the project naming rules on every source file, so a violation fails the test run
// instead of relying on review:
//   classes start with c_, structs end with _t, enums / namespaces / files are snake_case.

namespace fs = std::filesystem;

namespace {

fs::path source_root() {
    // tests/test_conventions.cpp → repository root.
    return fs::path{__FILE__}.parent_path().parent_path();
}

bool is_snake_case(const std::string& name) {
    static const std::regex pattern{"^[a-z][a-z0-9_]*$"};
    return std::regex_match(name, pattern);
}

// Comments and string literals may mention "class" or "struct" in prose; drop them first.
std::string strip_comments_and_strings(const std::string& code) {
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

} // namespace

glaipnir_test(conventions_names_follow_project_rules) {
    const std::regex type_declaration{R"(\b(enum\s+class|class|struct)\s+(\[\[\w+\]\]\s+)?([A-Za-z_]\w*)\s*(final\s*)?[:{;])"};
    const std::regex namespace_declaration{R"(\bnamespace\s+([A-Za-z_][\w:]*)\s*\{)"};
    int files_checked = 0;
    for (const auto* directory : {"include", "src", "cli", "tests"}) {
        for (const auto& entry : fs::recursive_directory_iterator(source_root() / directory)) {
            const auto extension = entry.path().extension();
            if (!entry.is_regular_file() || (extension != ".hpp" && extension != ".cpp")) {
                continue;
            }
            ++files_checked;
            const auto file = entry.path().filename().string();
            if (!is_snake_case(entry.path().stem().string())) {
                glaipnir::test::report_failure(__FILE__, __LINE__, "file name not snake_case: " + file);
            }
            const auto code = strip_comments_and_strings(glaipnir::test::read_file(entry.path()));
            for (std::sregex_iterator it{code.begin(), code.end(), type_declaration}, end; it != end; ++it) {
                const std::string kind = (*it)[1];
                const std::string name = (*it)[3];
                const bool ok = kind == "class"    ? name.starts_with("c_") && is_snake_case(name)
                                : kind == "struct" ? name.ends_with("_t") && is_snake_case(name)
                                                   : is_snake_case(name);
                if (!ok) {
                    glaipnir::test::report_failure(__FILE__, __LINE__, file + ": " + kind + " '" + name + "' breaks naming rules");
                }
            }
            for (std::sregex_iterator it{code.begin(), code.end(), namespace_declaration}, end; it != end; ++it) {
                std::string name = (*it)[1];
                for (auto& c : name) {
                    c = c == ':' ? '_' : c;
                }
                if (!is_snake_case(name)) {
                    glaipnir::test::report_failure(__FILE__, __LINE__, file + ": namespace '" + std::string{(*it)[1]} + "' not snake_case");
                }
            }
        }
    }
    glaipnir_check(files_checked > 20);
}
