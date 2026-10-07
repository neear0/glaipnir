#include "glaipnir/platform/windows/command_line.hpp"

#include "platform/windows/detail/path_search.hpp"
#include "platform/windows/detail/win_util.hpp"

#include <optional>
#include <system_error>

using glaipnir::core::error_code;
using glaipnir::core::result_t;

std::wstring glaipnir::platform::windows::quote_argument(std::wstring_view argument) {
    if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring{argument};
    }
    std::wstring quoted = L"\"";
    for (std::size_t i = 0;; ++i) {
        std::size_t backslashes = 0;
        while (i < argument.size() && argument[i] == L'\\') {
            ++i;
            ++backslashes;
        }
        if (i == argument.size()) {
            quoted.append(backslashes * 2, L'\\');
            break;
        }
        if (argument[i] == L'"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(L'"');
        } else {
            quoted.append(backslashes, L'\\');
            quoted.push_back(argument[i]);
        }
    }
    quoted.push_back(L'"');
    return quoted;
}

result_t<std::wstring> glaipnir::platform::windows::build_command_line(const std::vector<std::wstring>& argv) {
    if (argv.empty()) {
        return core::make_error(error_code::invalid_argument, "command is empty");
    }
    if (argv.front().find(L'"') != std::wstring::npos) {
        return core::make_error(error_code::invalid_argument, "program name must not contain '\"'");
    }
    std::wstring line;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        if (argv[i].find(L'\0') != std::wstring::npos) {
            return core::make_error(error_code::invalid_argument, "arguments must not contain NUL characters");
        }
        if (i > 0) {
            line.push_back(L' ');
            line += quote_argument(argv[i]);
            continue;
        }
        const bool needs_quotes = argv[0].empty() || argv[0].find_first_of(L" \t") != std::wstring::npos;
        line += needs_quotes ? L"\"" + argv[0] + L"\"" : argv[0];
    }
    if (line.size() >= 32767) {
        return core::make_error(error_code::invalid_argument, "command line exceeds the Windows limit of 32767 characters");
    }
    return line;
}

result_t<std::filesystem::path> glaipnir::platform::windows::resolve_executable(std::wstring_view name,
                                                                              std::wstring_view search_path,
                                                                              std::wstring_view extensions) {
    if (name.empty()) {
        return core::make_error(error_code::invalid_argument, "program name is empty");
    }
    const std::filesystem::path requested{name};
    std::vector<std::wstring> suffixes{L""};
    if (!requested.has_extension()) {
        for (auto& extension : detail::split_list(extensions.empty() ? std::wstring_view{L".COM;.EXE"} : extensions, L';')) {
            suffixes.push_back(std::move(extension));
        }
    }
    const auto try_candidates = [&](const std::filesystem::path& base) -> std::optional<std::filesystem::path> {
        for (const auto& suffix : suffixes) {
            std::filesystem::path candidate = base;
            candidate += suffix;
            if (detail::is_existing_file(candidate)) {
                std::error_code ec;
                auto absolute = std::filesystem::absolute(candidate, ec);
                return ec ? candidate : absolute;
            }
        }
        return std::nullopt;
    };

    if (requested.has_parent_path() || requested.is_absolute()) {
        if (auto found = try_candidates(requested)) {
            return *found;
        }
    } else {
        for (const auto& directory : detail::split_list(search_path, L';')) {
            if (auto found = try_candidates(std::filesystem::path{directory} / requested)) {
                return *found;
            }
        }
    }
    return core::make_error(error_code::not_found, "program '" + detail::from_wide(name) + "' not found");
}
