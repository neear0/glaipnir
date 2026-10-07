#include "platform/windows/detail/c_attribute_list.hpp"

#include <string>
#include <utility>

glaipnir::core::result_t<glaipnir::platform::windows::detail::c_attribute_list>
glaipnir::platform::windows::detail::c_attribute_list::create(DWORD count) {
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, count, 0, &size);
    c_attribute_list list;
    list.storage_.resize(size);
    if (!InitializeProcThreadAttributeList(list.get(), count, 0, &size)) {
        return last_error("cannot initialize process attributes");
    }
    list.initialized_ = true;
    return list;
}

glaipnir::platform::windows::detail::c_attribute_list::c_attribute_list(c_attribute_list&& other) noexcept
    : storage_(std::move(other.storage_)), initialized_(std::exchange(other.initialized_, false)) {}

glaipnir::platform::windows::detail::c_attribute_list::~c_attribute_list() {
    if (initialized_) {
        DeleteProcThreadAttributeList(get());
    }
}

LPPROC_THREAD_ATTRIBUTE_LIST glaipnir::platform::windows::detail::c_attribute_list::get() noexcept {
    return reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
}

glaipnir::core::result_t<void> glaipnir::platform::windows::detail::c_attribute_list::set(DWORD_PTR attribute, void* value,
                                                                                        SIZE_T size, std::string_view what) {
    if (!UpdateProcThreadAttribute(get(), 0, attribute, value, size, nullptr, nullptr)) {
        return last_error("cannot set process attribute " + std::string{what});
    }
    return core::ok();
}
