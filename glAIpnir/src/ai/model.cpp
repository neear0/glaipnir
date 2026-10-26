#include "harness/ai/model.hpp"
#include "harness/core/util.hpp"
#include <set>

harness::ai::c_model_client::c_model_client(harness::profile_t profile, std::shared_ptr<c_http_transport> transport)
    : profile_(std::move(profile)), transport_(std::move(transport)) {}
harness::json_t harness::ai::c_model_client::request_body(const std::vector<harness::message_t>& messages, const harness::json_t& tools) const {
    json_t wire_tools = json_t::array();
    for (const auto& tool : tools) {
        if (profile_.provider == "openai") wire_tools.push_back({{"type", "function"}, {"name", tool.at("name")},
            {"description", tool.at("description")}, {"parameters", tool.at("parameters")}, {"strict", false}});
        else if (profile_.provider == "anthropic") wire_tools.push_back({{"name", tool.at("name")},
            {"description", tool.at("description")}, {"input_schema", tool.at("parameters")}});
        else wire_tools.push_back({{"type", "function"}, {"function", tool}});
    }
    json_t body = {{"model", profile_.model}, {"tools", wire_tools}};
    json_t history = json_t::array(); std::string system;
    for (const auto& message : messages) {
        const bool native = message.native.is_object() && message.native.value("provider", "") == profile_.provider;
        if (message.role == "system") { system += message.text + "\n"; continue; }
        if (profile_.provider == "openai") {
            if (message.role == "tool") history.push_back({{"type", "function_call_output"}, {"call_id", message.call_id}, {"output", message.text}});
            else if (message.role == "assistant" && native) for (const auto& item : message.native.at("output")) history.push_back(item);
            else {
                if (!message.text.empty()) history.push_back({{"role", message.role}, {"content", message.text}});
                for (const auto& call : message.calls) history.push_back({{"type", "function_call"}, {"call_id", call.id}, {"name", call.name}, {"arguments", dump_json(call.arguments)}});
            }
        } else if (profile_.provider == "anthropic") {
            if (message.role == "tool") {
                json_t result = {{"type", "tool_result"}, {"tool_use_id", message.call_id}, {"content", message.text}, {"is_error", message.is_error}};
                if (!history.empty() && history.back().at("role") == "user" && history.back().at("content").is_array() &&
                    !history.back().at("content").empty() && history.back().at("content").front().value("type", "") == "tool_result") history.back()["content"].push_back(result);
                else history.push_back({{"role", "user"}, {"content", json_t::array({result})}});
            } else {
                json_t content = json_t::array();
                if (native) content = message.native.at("content");
                else {
                    if (!message.text.empty()) content.push_back({{"type", "text"}, {"text", message.text}});
                    for (const auto& call : message.calls) content.push_back({{"type", "tool_use"}, {"id", call.id}, {"name", call.name}, {"input", call.arguments}});
                }
                history.push_back({{"role", message.role}, {"content", content}});
            }
        } else {
            if (message.role == "assistant" && native) history.push_back(message.native.at("message"));
            else {
                json_t item = {{"role", message.role}, {"content", message.text}};
                if (message.role == "tool") item["tool_name"] = message.tool_name;
                if (!message.calls.empty()) {
                    item["tool_calls"] = json_t::array();
                    for (const auto& call : message.calls) item["tool_calls"].push_back({{"function", {{"name", call.name}, {"arguments", call.arguments}}}});
                }
                history.push_back(item);
            }
        }
    }
    if (profile_.provider == "openai") {
        body["instructions"] = system; body["input"] = history; body["store"] = false; body["max_output_tokens"] = profile_.max_output_tokens;
        body["include"] = {"reasoning.encrypted_content"};
    } else if (profile_.provider == "anthropic") {
        body["system"] = system; body["messages"] = history; body["max_tokens"] = profile_.max_output_tokens;
    } else {
        if (!system.empty()) history.insert(history.begin(), {{"role", "system"}, {"content", system}});
        body["messages"] = history; body["stream"] = false; body["options"] = {{"num_predict", profile_.max_output_tokens}};
    }
    return body;
}
harness::model_reply_t harness::ai::c_model_client::parse_reply(const harness::json_t& response) const {
    model_reply_t reply; reply.message.role = "assistant";
    reply.message.native = {{"provider", profile_.provider}};
    auto metadata = response;
    metadata.erase("output"); metadata.erase("content"); metadata.erase("message");
    reply.message.native["metadata"] = std::move(metadata);
    if (profile_.provider == "openai") {
        reply.status = response.value("status", "completed");
        reply.message.native["output"] = response.at("output");
        for (const auto& item : response.at("output")) {
            const auto type = item.at("type").get<std::string>();
            if (type == "function_call") {
                json_t arguments;
                try { arguments = json_t::parse(item.at("arguments").get<std::string>()); }
                catch (const json_t::exception&) { arguments = item.at("arguments"); }
                reply.message.calls.push_back({item.at("call_id"), item.at("name"), arguments});
            } else if (type == "message") for (const auto& part : item.at("content")) {
                if (part.value("type", "") == "output_text") reply.message.text += part.at("text").get<std::string>();
                if (part.value("type", "") == "refusal") reply.message.text += part.at("refusal").get<std::string>();
            }
        }
    } else if (profile_.provider == "anthropic") {
        reply.status = response.at("stop_reason"); reply.message.native["content"] = response.at("content");
        for (const auto& item : response.at("content")) {
            if (item.at("type") == "text") reply.message.text += item.at("text").get<std::string>();
            else if (item.at("type") == "tool_use") reply.message.calls.push_back({item.at("id"), item.at("name"), item.at("input")});
        }
    } else {
        if (!response.value("done", false)) throw std::runtime_error("Ollama returned an incomplete response");
        reply.status = response.value("done_reason", "stop");
        const auto& message = response.at("message"); reply.message.native["message"] = message;
        reply.message.text = message.value("content", "");
        for (const auto& call : message.value("tool_calls", json_t::array())) {
            const auto& function = call.at("function");
            reply.message.calls.push_back({new_id(), function.at("name"), function.at("arguments")});
        }
    }
    std::set<std::string> ids;
    if (reply.message.calls.size() > 64) throw std::runtime_error("Model returned more than 64 tool calls");
    for (const auto& call : reply.message.calls) if (call.id.empty() || call.name.empty() || !ids.insert(call.id).second)
        throw std::runtime_error("Model returned invalid or duplicate tool-call IDs");
    return reply;
}
harness::model_reply_t harness::ai::c_model_client::complete(const std::vector<harness::message_t>& messages, const harness::json_t& tools,
    const harness::limits_t& limits, const std::atomic_bool& cancelled) const {
    headers_t headers{{"Content-Type", "application/json"}};
    if (!profile_.key_env.empty()) {
        auto key_name = widen(profile_.key_env); DWORD size = GetEnvironmentVariableW(key_name.c_str(), nullptr, 0);
        if (!size) throw std::runtime_error("Missing environment variable: " + profile_.key_env);
        std::wstring key(size, L'\0'); GetEnvironmentVariableW(key_name.c_str(), key.data(), size); key.resize(size - 1);
        auto secret = narrow(key);
        if (secret.find_first_of("\r\n") != std::string::npos) throw std::runtime_error("Invalid credential");
        headers[profile_.provider == "anthropic" ? "x-api-key" : "Authorization"] = profile_.provider == "anthropic" ? secret : "Bearer " + secret;
    }
    if (profile_.provider == "anthropic") headers["anthropic-version"] = "2023-06-01";
    return parse_reply(transport_->post(profile_.endpoint, headers, request_body(messages, tools), limits.http_timeout_ms, cancelled));
}
