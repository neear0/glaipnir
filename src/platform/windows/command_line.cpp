#include "glaipnir/platform/windows/command_line.hpp"

#include "win_util.hpp"

#include <optional>
#include <system_error>

namespace glaipnir::platform::windows {

using core::error_code;
using core::result_t;

namespace fs = std::filesystem;

namespace {

std::vector<std::wstring> split(std::wstring_view text, wchar_t separator) {
    std::vector<std::wstring> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto end = text.find(separator, start);
        const auto part = text.substr(start, end == std::wstring_view::npos ? std::wstring_view::npos : end - start);
        if (!part.empty()) {
            parts.emplace_back(part);
        }
        if (end == std::wstring_view::npos) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

bool is_existing_file(const fs::path& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec);
}

} // namespace

std::wstring quote_argument(std::wstring_view argument) {
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
            // Backslashes before the closing quote must be doubled or they would escape it.
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

result_t<std::wstring> build_command_line(const std::vector<std::wstring>& argv) {
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
        // The program name ends at the first space (or the closing quote) with no escapes.
        const bool needs_quotes = argv[0].empty() || argv[0].find_first_of(L" \t") != std::wstring::npos;
        line += needs_quotes ? L"\"" + argv[0] + L"\"" : argv[0];
    }
    if (line.size() >= 32767) {
        return core::make_error(error_code::invalid_argument, "command line exceeds the Windows limit of 32767 characters");
    }
    return line;
}

result_t<fs::path> resolve_executable(std::wstring_view name, std::wstring_view search_path, std::wstring_view extensions) {
    if (name.empty()) {
        return core::make_error(error_code::invalid_argument, "program name is empty");
    }
    const fs::path requested{name};
    std::vector<std::wstring> suffixes{L""};
    if (!requested.has_extension()) {
        for (auto& extension : split(extensions.empty() ? std::wstring_view{L".COM;.EXE"} : extensions, L';')) {
            suffixes.push_back(std::move(extension));
        }
    }
    const auto try_candidates = [&](const fs::path& base) -> std::optional<fs::path> {
        for (const auto& suffix : suffixes) {
            fs::path candidate = base;
            candidate += suffix;
            if (is_existing_file(candidate)) {
                std::error_code ec;
                auto absolute = fs::absolute(candidate, ec);
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
        for (const auto& directory : split(search_path, L';')) {
            if (auto found = try_candidates(fs::path{directory} / requested)) {
                return *found;
            }
        }
    }
    return core::make_error(error_code::not_found, "program '" + from_wide(name) + "' not found");
}

} // namespace glaipnir::platform::windows
