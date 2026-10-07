#include "glaipnir/platform/windows/c_app_container.hpp"

#include "win_util.hpp"

#include <sddl.h>
#include <userenv.h>

namespace glaipnir::platform::windows {

using core::error_code;
using core::result_t;

void c_app_container::sid_deleter_t::operator()(void* sid) const noexcept {
    if (sid != nullptr) {
        FreeSid(sid);
    }
}

result_t<c_app_container> c_app_container::create_or_open(std::string_view moniker) {
    const std::wstring wide_moniker = to_wide(moniker);
    PSID sid = nullptr;
    // No capabilities are baked into the profile; they are passed per process at launch, so a
    // policy change takes effect on the next run without recreating the profile.
    HRESULT hr = CreateAppContainerProfile(wide_moniker.c_str(), wide_moniker.c_str(), L"glaipnir sandbox session",
                                           nullptr, 0, &sid);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        hr = DeriveAppContainerSidFromAppContainerName(wide_moniker.c_str(), &sid);
    }
    if (FAILED(hr)) {
        return win32_error("cannot create AppContainer profile '" + std::string{moniker} + "'", static_cast<DWORD>(hr));
    }

    wchar_t* sid_text = nullptr;
    if (!ConvertSidToStringSidW(sid, &sid_text)) {
        auto error = last_error("cannot format AppContainer SID");
        FreeSid(sid);
        return error;
    }
    std::string sid_string = from_wide(sid_text);
    LocalFree(sid_text);
    return c_app_container{std::string{moniker}, sid, std::move(sid_string)};
}

result_t<void> c_app_container::remove(std::string_view moniker) {
    const HRESULT hr = DeleteAppContainerProfile(to_wide(moniker).c_str());
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        return win32_error("cannot delete AppContainer profile '" + std::string{moniker} + "'", static_cast<DWORD>(hr));
    }
    return core::ok();
}

result_t<std::filesystem::path> c_app_container::folder() const {
    wchar_t* path = nullptr;
    const HRESULT hr = GetAppContainerFolderPath(to_wide(sid_string_).c_str(), &path);
    if (FAILED(hr)) {
        return win32_error("cannot locate AppContainer folder", static_cast<DWORD>(hr));
    }
    std::filesystem::path folder{path};
    CoTaskMemFree(path);
    return folder;
}

} // namespace glaipnir::platform::windows
