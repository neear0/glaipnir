#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::platform::windows {

class c_app_container {
public:
    static core::result_t<c_app_container> create_or_open(std::string_view moniker);

    static core::result_t<void> remove(std::string_view moniker);

    void* sid() const noexcept { return sid_.get(); }
    const std::string& sid_string() const noexcept { return sid_string_; }
    const std::string& moniker() const noexcept { return moniker_; }

    core::result_t<std::filesystem::path> folder() const;

private:
    struct sid_deleter_t {
        void operator()(void* sid) const noexcept;
    };

    c_app_container(std::string moniker, void* sid, std::string sid_string)
        : moniker_(std::move(moniker)), sid_(sid), sid_string_(std::move(sid_string)) {}

    std::string moniker_;
    std::unique_ptr<void, sid_deleter_t> sid_;
    std::string sid_string_;
};

}
