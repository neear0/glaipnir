#include "support/test_harness.hpp"

#include <map>
#include <regex>

#include "support/source_scan.hpp"

using glaipnir::test::is_snake_case;
using glaipnir::test::report_failure;

glaipnir_test(conventions_names_and_layout_follow_project_rules) {
    const std::regex type_declaration{R"(\b(enum\s+class|class|struct)\s+(\[\[\w+\]\]\s+)?([A-Za-z_]\w*)\s*(final\s*)?([{;]|:(?!:)))"};
    const std::regex namespace_declaration{R"(\bnamespace\s+([A-Za-z_][\w:]*)\s*\{)"};
    const std::regex namespace_keyword{R"(\bnamespace\b)"};
    int files_checked = 0;
    for (const auto* directory : {"include", "src", "cli", "tests"}) {
        std::map<std::string, std::string> cpp_stems;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(glaipnir::test::source_root() / directory)) {
            if (entry.path().extension() == ".cpp") {
                const auto [existing, inserted] = cpp_stems.emplace(entry.path().stem().string(), entry.path().generic_string());
                if (!inserted) {
                    report_failure(__FILE__, __LINE__, "duplicate .cpp name in one project: " + existing->second + " and " +
                                                           entry.path().generic_string());
                }
            }
        }
        for (const auto& entry : std::filesystem::recursive_directory_iterator(glaipnir::test::source_root() / directory)) {
            const auto extension = entry.path().extension();
            if (!entry.is_regular_file() || (extension != ".hpp" && extension != ".cpp")) {
                continue;
            }
            ++files_checked;
            const auto file = std::filesystem::relative(entry.path(), glaipnir::test::source_root()).generic_string();
            if (!is_snake_case(entry.path().stem().string())) {
                report_failure(__FILE__, __LINE__, "file name not snake_case: " + file);
            }
            const auto code = glaipnir::test::strip_comments_and_strings(glaipnir::test::read_file(entry.path()));

            if (extension == ".cpp" && std::regex_search(code, namespace_keyword)) {
                report_failure(__FILE__, __LINE__,
                               file + ": .cpp files must not use `namespace`; define with qualified names instead");
            }
            for (std::sregex_iterator it{code.begin(), code.end(), type_declaration}, end; it != end; ++it) {
                const std::string kind = (*it)[1];
                const std::string name = (*it)[3];
                const bool ok = kind == "class"    ? name.starts_with("c_") && is_snake_case(name)
                                : kind == "struct" ? name.ends_with("_t") && is_snake_case(name)
                                                   : is_snake_case(name);
                if (!ok) {
                    report_failure(__FILE__, __LINE__, file + ": " + kind + " '" + name + "' breaks naming rules");
                }
            }
            for (std::sregex_iterator it{code.begin(), code.end(), namespace_declaration}, end; it != end; ++it) {
                std::string name = (*it)[1];
                for (auto& c : name) {
                    c = c == ':' ? '_' : c;
                }
                if (!is_snake_case(name)) {
                    report_failure(__FILE__, __LINE__, file + ": namespace '" + std::string{(*it)[1]} + "' not snake_case");
                }
            }
        }
    }
    glaipnir_check(files_checked > 40);
}
