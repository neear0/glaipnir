#include "harness/windows/analysis.hpp"
#include <algorithm>

static std::string text_or_empty(const wchar_t* value) { return value ? harness::narrow(value) : ""; }
harness::json_t harness::windows::decode_service_config(const QUERY_SERVICE_CONFIGW& config) {
    json_t dependencies = json_t::array();
    if (config.lpDependencies) {
        const wchar_t* entry = config.lpDependencies;
        while (*entry) { dependencies.push_back(narrow(entry)); entry += wcslen(entry) + 1; }
    }
    return {{"service_type", config.dwServiceType}, {"start_type", config.dwStartType}, {"error_control", config.dwErrorControl},
        {"binary_path", text_or_empty(config.lpBinaryPathName)}, {"account", text_or_empty(config.lpServiceStartName)},
        {"display_name", text_or_empty(config.lpDisplayName)}, {"load_order_group", text_or_empty(config.lpLoadOrderGroup)}, {"dependencies", dependencies}};
}
static harness::json_t service_status(const SERVICE_STATUS_PROCESS& status) {
    return {{"state", status.dwCurrentState}, {"pid", status.dwProcessId}, {"service_type", status.dwServiceType},
        {"controls_accepted", status.dwControlsAccepted}, {"win32_exit_code", status.dwWin32ExitCode}, {"service_exit_code", status.dwServiceSpecificExitCode}};
}
harness::json_t harness::windows::service_analysis(const std::string& name, const harness::json_t& args,
    const harness::limits_t& limits, const std::atomic_bool& cancelled) {
    c_service_handle manager(OpenSCManagerW(nullptr, nullptr, name == "service_list" ? SC_MANAGER_ENUMERATE_SERVICE : SC_MANAGER_CONNECT));
    require_win(manager.get() != nullptr, "OpenSCManager");
    if (name == "service_list") {
        std::vector<json_t> services; DWORD resume = 0; std::vector<unsigned char> buffer(256 * 1024); json_t errors = json_t::array();
        do {
            DWORD needed{}, count{};
            BOOL success = EnumServicesStatusExW(manager.get(), SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
                buffer.data(), static_cast<DWORD>(buffer.size()), &needed, &count, &resume, nullptr);
            const auto error = success ? ERROR_SUCCESS : GetLastError();
            if (error != ERROR_SUCCESS && error != ERROR_MORE_DATA) {
                if (services.empty()) throw c_windows_error("EnumServicesStatusEx", error);
                errors.push_back(c_windows_error("EnumServicesStatusEx", error).result()); break;
            }
            const auto entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
            for (DWORD index = 0; index < count; ++index) {
                auto item = service_status(entries[index].ServiceStatusProcess);
                item["name"] = narrow(entries[index].lpServiceName); item["display_name"] = narrow(entries[index].lpDisplayName); services.push_back(std::move(item));
            }
            if (success) break;
            if (!count) { errors.push_back(c_windows_error("Service enumeration made no progress", ERROR_MORE_DATA).result()); break; }
        } while (!cancelled.load());
        std::sort(services.begin(), services.end(), [](const auto& left, const auto& right) { return left.at("name").template get<std::string>() < right.at("name").template get<std::string>(); });
        c_page page(args, limits);
        for (std::size_t index = 0; index < services.size() && !cancelled.load(); ++index) if (!page.add(std::move(services[index]), index)) break;
        auto result = page.finish(cancelled.load());
        if (!errors.empty()) { result["errors"] = errors; result["partial"] = true; }
        return result;
    }
    c_service_handle service(OpenServiceW(manager.get(), widen(args.at("name")).c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
    require_win(service.get() != nullptr, "OpenService");
    json_t result = {{"ok", true}, {"name", args.at("name")}}; json_t errors = json_t::array();
    SERVICE_STATUS_PROCESS status{}; DWORD needed{};
    if (QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &needed)) result.update(service_status(status));
    else errors.push_back(c_windows_error("QueryServiceStatusEx", GetLastError()).result());
    QueryServiceConfigW(service.get(), nullptr, 0, &needed);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed <= 1024 * 1024) {
        std::vector<unsigned char> config(needed);
        if (QueryServiceConfigW(service.get(), reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data()), static_cast<DWORD>(config.size()), &needed))
            result.update(decode_service_config(*reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data())));
        else errors.push_back(c_windows_error("QueryServiceConfig", GetLastError()).result());
    } else errors.push_back(c_windows_error("QueryServiceConfig size", GetLastError()).result());
    needed = 0; QueryServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &needed);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed <= 1024 * 1024) {
        std::vector<unsigned char> description(needed);
        if (QueryServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, description.data(), static_cast<DWORD>(description.size()), &needed))
            result["description"] = text_or_empty(reinterpret_cast<SERVICE_DESCRIPTIONW*>(description.data())->lpDescription);
        else errors.push_back(c_windows_error("QueryServiceConfig2", GetLastError()).result());
    } else errors.push_back(c_windows_error("QueryServiceConfig2 size", GetLastError()).result());
    if (!errors.empty()) { result["partial"] = true; result["errors"] = errors; }
    return result;
}
