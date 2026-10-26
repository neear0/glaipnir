#include "harness/core/util.hpp"
#include <bcrypt.h>
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>

void harness::check_win(bool success, const char* operation) {
    if (!success) throw std::runtime_error(std::string(operation) + " failed (Windows error " + std::to_string(GetLastError()) + ")");
}
std::wstring harness::widen(const std::string& value) {
    if (value.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    check_win(size != 0, "UTF-8 conversion");
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}
std::string harness::narrow(const std::wstring& value) {
    if (value.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    check_win(size != 0, "UTF-16 conversion");
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}
std::string harness::path_text(const std::filesystem::path& path) { return narrow(path.wstring()); }
std::string harness::timestamp() {
    SYSTEMTIME time{}; GetSystemTime(&time);
    char text[40]{};
    sprintf_s(text, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
    return text;
}
std::string harness::new_id() {
    std::array<unsigned char, 16> bytes{};
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("Random ID generation failed");
    std::ostringstream text;
    for (auto byte : bytes) text << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return text.str();
}
std::string harness::dump_json(const harness::json_t& value, int indent) {
    return value.dump(indent, ' ', false, json_t::error_handler_t::replace);
}
harness::json_t harness::read_json(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot read " + path_text(path));
    return json_t::parse(stream);
}
void harness::write_text(const std::filesystem::path& path, const std::string& value) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream || !(stream << value)) throw std::runtime_error("Cannot write " + path_text(path));
    stream.close();
    if (!stream) throw std::runtime_error("Cannot finish writing " + path_text(path));
}
std::string harness::sha256(const std::filesystem::path& path, const std::atomic_bool* cancelled) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot hash " + path_text(path));
    BCRYPT_ALG_HANDLE algorithm{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) throw std::runtime_error("SHA-256 unavailable");
    BCRYPT_HASH_HANDLE hash{};
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0); throw std::runtime_error("Cannot initialize SHA-256");
    }
    try {
        std::array<char, 65536> buffer{};
        while (stream) {
            if (cancelled && cancelled->load()) throw std::runtime_error("Cancelled");
            stream.read(buffer.data(), buffer.size());
            if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(stream.gcount()), 0) < 0)
                throw std::runtime_error("SHA-256 update failed");
        }
        if (!stream.eof()) throw std::runtime_error("File read failed while hashing");
        std::array<unsigned char, 32> digest{};
        if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) throw std::runtime_error("SHA-256 finalization failed");
        BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
        std::ostringstream result;
        for (auto byte : digest) result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        return result.str();
    } catch (...) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); throw; }
}
std::wstring harness::quote_argument(const std::wstring& value) {
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (auto character : value) {
        if (character == L'\\') { ++slashes; continue; }
        if (character == L'\"') { result.append(slashes * 2 + 1, L'\\'); result += character; }
        else { result.append(slashes, L'\\'); result += character; }
        slashes = 0;
    }
    result.append(slashes * 2, L'\\'); result += L'\"';
    return result;
}
harness::json_t harness::message_json(const harness::message_t& message) {
    json_t calls = json_t::array();
    for (const auto& call : message.calls) calls.push_back({{"id", call.id}, {"name", call.name}, {"arguments", call.arguments}});
    return {{"role", message.role}, {"text", message.text}, {"calls", calls}, {"call_id", message.call_id},
        {"tool_name", message.tool_name}, {"is_error", message.is_error}, {"native", message.native}};
}
harness::message_t harness::parse_message(const harness::json_t& value) {
    message_t message;
    message.role = value.at("role"); message.text = value.value("text", "");
    message.call_id = value.value("call_id", ""); message.tool_name = value.value("tool_name", "");
    message.is_error = value.value("is_error", false); message.native = value.value("native", json_t(nullptr));
    for (const auto& call : value.value("calls", json_t::array())) message.calls.push_back({call.at("id"), call.at("name"), call.at("arguments")});
    return message;
}
std::string harness::state_text(harness::task_state_t state) {
    switch (state) {
    case task_state_t::queued: return "queued";
    case task_state_t::running: return "running";
    case task_state_t::succeeded: return "succeeded";
    case task_state_t::failed: return "failed";
    case task_state_t::cancelled: return "cancelled";
    default: return "interrupted";
    }
}
harness::limits_t harness::parse_limits(const harness::json_t& config) {
    auto input = config.value("limits", json_t::object());
    limits_t limits;
    limits.operation_timeout_ms = input.value("operation_timeout_ms", 60000);
    limits.output_limit = input.value("output_limit", std::size_t{1024 * 1024});
    limits.http_timeout_ms = input.value("http_timeout_ms", 120000);
    limits.max_turns = input.value("max_turns", 32);
    if (limits.operation_timeout_ms < 1 || limits.output_limit < 1 || limits.output_limit > 64 * 1024 * 1024 ||
        limits.http_timeout_ms < 1 || limits.max_turns < 1 || limits.max_turns > 10000) throw std::runtime_error("Invalid execution limits");
    return limits;
}
harness::profile_t harness::parse_profile(const harness::json_t& config, const std::string& name) {
    const auto& input = config.at("profiles").at(name);
    profile_t profile;
    profile.provider = input.at("provider"); profile.model = input.at("model");
    if (profile.provider != "openai" && profile.provider != "anthropic" && profile.provider != "ollama") throw std::runtime_error("Unknown provider");
    profile.endpoint = input.value("endpoint", profile.provider == "openai" ? "https://api.openai.com/v1/responses" :
        profile.provider == "anthropic" ? "https://api.anthropic.com/v1/messages" : "http://localhost:11434/api/chat");
    profile.key_env = input.value("key_env", profile.provider == "openai" ? "OPENAI_API_KEY" : profile.provider == "anthropic" ? "ANTHROPIC_API_KEY" : "");
    profile.max_output_tokens = input.value("max_output_tokens", 4096);
    if (profile.model.empty() || profile.max_output_tokens < 1) throw std::runtime_error("Model and positive max_output_tokens are required");
    return profile;
}
