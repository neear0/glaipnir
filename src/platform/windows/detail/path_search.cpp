#include "platform/windows/detail/path_search.hpp"

#include <system_error>

std::vector<std::wstring> glaipnir::platform::windows::detail::split_list(std::wstring_view text, wchar_t separator) {
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

bool glaipnir::platform::windows::detail::is_existing_file(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}
