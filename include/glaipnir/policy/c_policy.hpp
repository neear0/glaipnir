#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::policy {

struct host_context_t {
    std::filesystem::path home;
    std::filesystem::path cwd;
    std::filesystem::path state_root;

    static host_context_t detect(std::filesystem::path state_root);
};

class c_policy {
public:
    static c_policy deny_all();

    static core::result_t<c_policy> load_file(const std::filesystem::path& file, const host_context_t& host);

    static core::result_t<c_policy> parse(std::string_view text, const host_context_t& host);

    static core::result_t<c_policy> from_data(policy_t data, const host_context_t& host);

    const policy_t& data() const noexcept { return data_; }

    std::string to_toml() const;

    std::string digest() const;

private:
    explicit c_policy(policy_t data) : data_(std::move(data)) {}

    policy_t data_;
};

bool looks_like_secret_name(std::string_view name);

std::vector<std::filesystem::path> sensitive_paths(const host_context_t& host);

std::string_view to_string(isolation_backend backend) noexcept;
std::string_view to_string(network_mode mode) noexcept;
std::string_view to_string(access_mode mode) noexcept;

}
