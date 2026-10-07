#include "glaipnir/platform/windows/c_app_container.hpp"

#include "platform/windows/detail/win_util.hpp"

#include <sddl.h>
#include <userenv.h>

using glaipnir::core::result_t;

void glaipnir::platform::windows::c_app_container::sid_deleter_t::operator()(void* sid) const noexcept {
    if (sid != nullptr) {
        FreeSid(sid);
    }
}

result_t<glaipnir::platform::windows::c_app_container>
glaipnir::platform::windows::c_app_container::create_or_open(std::string_view moniker) {
    const std::wstring wide_moniker = detail::to_wide(moniker);
    PSID sid = nullptr;
    HRESULT hr = CreateAppContainerProfile(wide_moniker.c_str(), wide_moniker.c_str(), L"glaipnir sandbox session",
                                           nullptr, 0, &sid);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        hr = DeriveAppContainerSidFromAppContainerName(wide_moniker.c_str(), &sid);
    }
    if (FAILED(hr)) {
        return detail::win32_error("cannot create AppContainer profile '" + std::string{moniker} + "'", static_cast<DWORD>(hr));
    }

    wchar_t* sid_text = nullptr;
    if (!ConvertSidToStringSidW(sid, &sid_text)) {
        auto error = detail::last_error("cannot format AppContainer SID");
        FreeSid(sid);
        return error;
    }
    std::string sid_string = detail::from_wide(sid_text);
    LocalFree(sid_text);
    return c_app_container{std::string{moniker}, sid, std::move(sid_string)};
}

result_t<void> glaipnir::platform::windows::c_app_container::remove(std::string_view moniker) {
    const HRESULT hr = DeleteAppContainerProfile(detail::to_wide(moniker).c_str());
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        return detail::win32_error("cannot delete AppContainer profile '" + std::string{moniker} + "'", static_cast<DWORD>(hr));
    }
    return core::ok();
}

result_t<std::filesystem::path> glaipnir::platform::windows::c_app_container::folder() const {
    wchar_t* path = nullptr;
    const HRESULT hr = GetAppContainerFolderPath(detail::to_wide(sid_string_).c_str(), &path);
    if (FAILED(hr)) {
        return detail::win32_error("cannot locate AppContainer folder", static_cast<DWORD>(hr));
    }
    std::filesystem::path folder{path};
    CoTaskMemFree(path);
    return folder;
}
