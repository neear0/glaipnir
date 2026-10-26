#pragma once
#include "harness/core/types.hpp"
#include <map>
#include <memory>

namespace harness::ai {
using headers_t = std::map<std::string, std::string>;
class c_http_transport {
public:
    virtual ~c_http_transport() = default;
    virtual json_t post(const std::string& endpoint, const headers_t& headers, const json_t& body,
        int timeout_ms, const std::atomic_bool& cancelled) = 0;
};
class c_winhttp_transport final : public c_http_transport {
public:
    json_t post(const std::string& endpoint, const headers_t& headers, const json_t& body,
        int timeout_ms, const std::atomic_bool& cancelled) override;
};
class c_model_client {
public:
    c_model_client(profile_t profile, std::shared_ptr<c_http_transport> transport = std::make_shared<c_winhttp_transport>());
    model_reply_t complete(const std::vector<message_t>& messages, const json_t& tools,
        const limits_t& limits, const std::atomic_bool& cancelled) const;
    json_t request_body(const std::vector<message_t>& messages, const json_t& tools) const;
    model_reply_t parse_reply(const json_t& response) const;
    const profile_t& profile() const noexcept { return profile_; }
private:
    profile_t profile_;
    std::shared_ptr<c_http_transport> transport_;
};
}
