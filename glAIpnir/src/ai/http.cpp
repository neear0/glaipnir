#include "harness/ai/model.hpp"
#include "harness/core/util.hpp"
#include <winhttp.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <system_error>

static void http_check(BOOL result) {
    if (!result) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "HTTP request");
}
harness::json_t harness::ai::c_winhttp_transport::post(const std::string& endpoint, const harness::ai::headers_t& headers,
    const harness::json_t& body, int timeout_ms, const std::atomic_bool& cancelled) {
    const auto url = widen(endpoint);
    URL_COMPONENTS components{}; components.dwStructSize = sizeof(components);
    components.dwHostNameLength = components.dwUrlPathLength = components.dwExtraInfoLength = components.dwUserNameLength = components.dwPasswordLength = static_cast<DWORD>(-1);
    http_check(WinHttpCrackUrl(url.c_str(), 0, 0, &components));
    if (components.dwUserNameLength || components.dwPasswordLength || components.dwExtraInfoLength)
        throw std::runtime_error("Endpoint must not contain credentials, query, or fragment");
    const bool secure = components.nScheme == INTERNET_SCHEME_HTTPS;
    const auto host = std::wstring(components.lpszHostName, components.dwHostNameLength);
    if (!secure && (components.nScheme != INTERNET_SCHEME_HTTP || (host != L"localhost" && host != L"127.0.0.1" && host != L"[::1]")))
        throw std::runtime_error("HTTP is supported only for loopback endpoints; use HTTPS for remote models");
    const auto path = std::wstring(components.lpszUrlPath, components.dwUrlPathLength);
    const auto serialized = dump_json(body);
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (cancelled.load()) throw std::runtime_error("Cancelled");
        const auto user_agent = widen(std::string("glAIpnir/") + HARNESS_VERSION);
        HINTERNET session = WinHttpOpen(user_agent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        http_check(session != nullptr);
        HINTERNET connection{}; std::atomic<HINTERNET> request{};
        bool timed_out = false;
        try {
            http_check(WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms));
            connection = WinHttpConnect(session, host.c_str(), components.nPort, 0); http_check(connection != nullptr);
            HINTERNET active = WinHttpOpenRequest(connection, L"POST", path.empty() ? L"/" : path.c_str(), nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
            http_check(active != nullptr); request.store(active);
            DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            http_check(WinHttpSetOption(active, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)));
            std::wstring wire_headers;
            for (const auto& [name, value] : headers) wire_headers += widen(name + ": " + value + "\r\n");
            if (!wire_headers.empty()) http_check(WinHttpAddRequestHeaders(active, wire_headers.c_str(), static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD));
            const auto start = std::chrono::steady_clock::now();
            std::jthread watcher([&](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    if (cancelled.load() || std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(timeout_ms)) {
                        if (!cancelled.load()) timed_out = true;
                        if (auto handle = request.exchange(nullptr)) WinHttpCloseHandle(handle);
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            });
            http_check(WinHttpSendRequest(active, WINHTTP_NO_ADDITIONAL_HEADERS, 0, const_cast<char*>(serialized.data()),
                static_cast<DWORD>(serialized.size()), static_cast<DWORD>(serialized.size()), 0));
            http_check(WinHttpReceiveResponse(active, nullptr));
            DWORD status{}, size = sizeof(status);
            http_check(WinHttpQueryHeaders(active, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX));
            std::string response;
            for (;;) {
                DWORD available{}; http_check(WinHttpQueryDataAvailable(active, &available));
                if (!available) break;
                if (available > 16 * 1024 * 1024 || response.size() > 16 * 1024 * 1024 - available) throw std::runtime_error("Model response exceeds 16 MiB");
                const auto offset = response.size(); response.resize(offset + available);
                DWORD count{}; http_check(WinHttpReadData(active, response.data() + offset, available, &count)); response.resize(offset + count);
                if (!count) break;
            }
            watcher.request_stop(); watcher.join();
            if (auto handle = request.exchange(nullptr)) WinHttpCloseHandle(handle);
            WinHttpCloseHandle(connection); connection = nullptr; WinHttpCloseHandle(session); session = nullptr;
            if (cancelled.load()) throw std::runtime_error("Cancelled");
            if (timed_out) throw std::runtime_error("HTTP timeout");
            if (status == 429 || status >= 500) {
                if (attempt == 2) throw std::runtime_error("Model HTTP " + std::to_string(status));
            } else {
                if (status < 200 || status >= 300) throw std::runtime_error("Model HTTP " + std::to_string(status));
                return json_t::parse(response);
            }
        } catch (const std::exception& failure) {
            const auto* network_error = dynamic_cast<const std::system_error*>(&failure);
            const auto error = network_error ? network_error->code().value() : 0;
            if (auto handle = request.exchange(nullptr)) WinHttpCloseHandle(handle);
            if (connection) WinHttpCloseHandle(connection); if (session) WinHttpCloseHandle(session);
            if (cancelled.load()) throw std::runtime_error("Cancelled");
            if (timed_out) throw std::runtime_error("HTTP timeout");
            // Only transport errors are retried; JSON/schema and HTTP 4xx failures are final.
            if (attempt == 2 || (error != ERROR_WINHTTP_CANNOT_CONNECT && error != ERROR_WINHTTP_CONNECTION_ERROR && error != ERROR_WINHTTP_TIMEOUT && error != ERROR_WINHTTP_NAME_NOT_RESOLVED)) throw;
        }
        for (int delay = 0; delay < (attempt + 1) * 25; ++delay) {
            if (cancelled.load()) throw std::runtime_error("Cancelled");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    throw std::runtime_error("Model request failed");
}
