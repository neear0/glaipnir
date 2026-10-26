#include "harness/windows/analysis.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>

void harness::windows::parse_registry_path(const std::string& path, HKEY& hive, std::wstring& subkey, std::string& canonical_hive) {
    const auto split = path.find('\\'); auto root = path.substr(0, split);
    std::transform(root.begin(), root.end(), root.begin(), [](unsigned char character) { return static_cast<char>(std::toupper(character)); });
    if (root == "HKCU" || root == "HKEY_CURRENT_USER") { hive = HKEY_CURRENT_USER; canonical_hive = "HKEY_CURRENT_USER"; }
    else if (root == "HKLM" || root == "HKEY_LOCAL_MACHINE") { hive = HKEY_LOCAL_MACHINE; canonical_hive = "HKEY_LOCAL_MACHINE"; }
    else if (root == "HKCR" || root == "HKEY_CLASSES_ROOT") { hive = HKEY_CLASSES_ROOT; canonical_hive = "HKEY_CLASSES_ROOT"; }
    else if (root == "HKU" || root == "HKEY_USERS") { hive = HKEY_USERS; canonical_hive = "HKEY_USERS"; }
    else if (root == "HKCC" || root == "HKEY_CURRENT_CONFIG") { hive = HKEY_CURRENT_CONFIG; canonical_hive = "HKEY_CURRENT_CONFIG"; }
    else throw c_windows_error("Unsupported local registry hive", ERROR_INVALID_PARAMETER);
    subkey = split == std::string::npos ? L"" : widen(path.substr(split + 1));
}
REGSAM harness::windows::registry_view(const std::string& view) {
    if (view == "native" || view == "64") return KEY_WOW64_64KEY;
    if (view == "32") return KEY_WOW64_32KEY;
    throw c_windows_error("Unknown registry view", ERROR_INVALID_PARAMETER);
}
harness::json_t harness::windows::decode_registry_value(DWORD type, const std::vector<unsigned char>& bytes) {
    json_t result = {{"type", type}, {"size", bytes.size()}, {"hex", bytes_hex(bytes.data(), bytes.size())}, {"malformed", false}};
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        result["type_name"] = type == REG_SZ ? "REG_SZ" : type == REG_EXPAND_SZ ? "REG_EXPAND_SZ" : "REG_MULTI_SZ";
        if (bytes.size() % sizeof(wchar_t)) { result["malformed"] = true; return result; }
        std::wstring text(bytes.size() / sizeof(wchar_t), L'\0'); if (!bytes.empty()) std::memcpy(text.data(), bytes.data(), bytes.size());
        const bool valid_utf16 = text.empty() || WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr) != 0;
        if (type == REG_MULTI_SZ) {
            const bool terminated = text.size() >= 2 && text.back() == L'\0' && text[text.size() - 2] == L'\0';
            result["malformed"] = !terminated || !valid_utf16; json_t values = json_t::array();
            for (std::size_t index = 0; index < text.size() && text[index];) {
                auto end = text.find(L'\0', index); if (end == std::wstring::npos) end = text.size();
                values.push_back(narrow(text.substr(index, end - index))); index = end + 1;
            }
            result["data"] = values;
        } else {
            result["malformed"] = text.empty() || text.back() != L'\0' || !valid_utf16;
            if (!text.empty() && text.back() == L'\0') text.pop_back();
            result["data"] = narrow(text); if (type == REG_EXPAND_SZ) result["expanded"] = false;
        }
    } else if (type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN || type == REG_QWORD) {
        result["type_name"] = type == REG_QWORD ? "REG_QWORD" : type == REG_DWORD ? "REG_DWORD" : "REG_DWORD_BIG_ENDIAN";
        const std::size_t expected = type == REG_QWORD ? 8 : 4;
        if (bytes.size() != expected) result["malformed"] = true;
        else {
            std::uint64_t number{};
            for (std::size_t index = 0; index < expected; ++index)
                number |= static_cast<std::uint64_t>(bytes[index]) << (8 * (type == REG_DWORD_BIG_ENDIAN ? expected - 1 - index : index));
            result["data"] = number;
        }
    } else result["type_name"] = type == REG_BINARY ? "REG_BINARY" : type == REG_NONE ? "REG_NONE" : "OTHER";
    return result;
}
harness::json_t harness::windows::registry_analysis(const std::string& name, const harness::json_t& args,
    const harness::limits_t& limits, const std::atomic_bool& cancelled) {
    HKEY hive{}; std::wstring subkey; std::string canonical;
    parse_registry_path(args.at("key"), hive, subkey, canonical); HKEY opened{};
    const auto view = args.value("view", "native");
    require_status(RegOpenKeyExW(hive, subkey.c_str(), 0, KEY_QUERY_VALUE | (name == "registry_list" ? KEY_ENUMERATE_SUB_KEYS : 0) | registry_view(view), &opened), "RegOpenKeyEx");
    c_registry_key key(opened);
    if (name == "registry_read") {
        const auto value_name = widen(args.at("name"));
        for (int attempt = 0; attempt < 4 && !cancelled.load(); ++attempt) {
            DWORD type{}, length{};
            require_status(RegQueryValueExW(key.get(), value_name.c_str(), nullptr, &type, nullptr, &length), "RegQueryValueEx size");
            if (length > limits.output_limit) throw c_windows_error("Registry value exceeds output_limit", ERROR_INSUFFICIENT_BUFFER);
            std::vector<unsigned char> bytes(length); DWORD actual = length;
            const auto status = RegQueryValueExW(key.get(), value_name.c_str(), nullptr, &type, bytes.empty() ? nullptr : bytes.data(), &actual);
            if (status == ERROR_MORE_DATA || actual > bytes.size()) continue;
            require_status(status, "RegQueryValueEx"); bytes.resize(actual);
            auto result = decode_registry_value(type, bytes); result["ok"] = true; result["name"] = args.at("name");
            result["key"] = args.at("key"); result["view"] = view == "native" ? "64" : view;
            if (dump_json(result).size() > limits.output_limit) throw c_windows_error("Decoded registry value exceeds output_limit", ERROR_INSUFFICIENT_BUFFER);
            return result;
        }
        if (cancelled.load()) return {{"ok", false}, {"cancelled", true}};
        throw c_windows_error("Registry value changed repeatedly", ERROR_MORE_DATA);
    }
    c_page page(args, limits); std::size_t index = 0; bool full = false; json_t errors = json_t::array();
    std::vector<wchar_t> buffer(32768);
    for (DWORD native_index = 0; !cancelled.load(); ++native_index) {
        DWORD length = static_cast<DWORD>(buffer.size()); FILETIME modified{};
        auto status = RegEnumKeyExW(key.get(), native_index, buffer.data(), &length, nullptr, nullptr, nullptr, &modified);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) { errors.push_back(c_windows_error("RegEnumKeyEx", status).result()); break; }
        if (!page.add({{"kind", "subkey"}, {"name", narrow(std::wstring(buffer.data(), length))}}, index++)) { full = true; break; }
    }
    if (!full) for (DWORD native_index = 0; !cancelled.load(); ++native_index) {
        DWORD length = static_cast<DWORD>(buffer.size()), type{}, size{};
        auto status = RegEnumValueW(key.get(), native_index, buffer.data(), &length, nullptr, &type, nullptr, &size);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) { errors.push_back(c_windows_error("RegEnumValue", status).result()); break; }
        if (!page.add({{"kind", "value"}, {"name", narrow(std::wstring(buffer.data(), length))}, {"type", type}, {"size", size}}, index++)) break;
    }
    auto result = page.finish(cancelled.load()); result["view"] = view == "native" ? "64" : view; result["key"] = args.at("key");
    if (!errors.empty()) { result["errors"] = errors; result["partial"] = true; }
    return result;
}
