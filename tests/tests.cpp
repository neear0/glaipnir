#include "support.hpp"
#include "harness/windows/tools.hpp"
#include <fstream>

harness::tests::c_http_fixture::c_http_fixture(std::vector<harness::tests::response_t> responses)
    : listener_(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) {
    require(listener_.get() != INVALID_SOCKET, "socket");
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(listener_.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != SOCKET_ERROR, "bind");
    int size = sizeof(address); require(getsockname(listener_.get(), reinterpret_cast<sockaddr*>(&address), &size) == 0, "getsockname");
    port_ = ntohs(address.sin_port); require(listen(listener_.get(), SOMAXCONN) == 0, "listen");
    server_ = std::jthread([this, responses = std::move(responses)](std::stop_token stop) {
        try {
            for (const auto& response : responses) {
                while (true) {
                    if (stop.stop_requested()) return;
                    fd_set read_set; FD_ZERO(&read_set); FD_SET(listener_.get(), &read_set); timeval timeout{0, 100000};
                    if (select(0, &read_set, nullptr, nullptr, &timeout) > 0) break;
                }
                c_socket client(accept(listener_.get(), nullptr, nullptr)); require(client.get() != INVALID_SOCKET, "accept");
                DWORD timeout = 2000; setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
                std::string request; std::array<char, 8192> bytes{}; std::size_t content_length = 0, split = std::string::npos;
                for (;;) {
                    const int received = recv(client.get(), bytes.data(), static_cast<int>(bytes.size()), 0); require(received > 0, "receive fixture request");
                    request.append(bytes.data(), received); require(request.size() < 16 * 1024 * 1024, "fixture request limit");
                    split = request.find("\r\n\r\n");
                    if (split != std::string::npos) {
                        const auto start = request.find("Content-Length:"); require(start != std::string::npos, "content length");
                        content_length = std::stoull(request.substr(start + 15));
                        if (request.size() >= split + 4 + content_length) break;
                    }
                }
                headers.push_back(request.substr(0, split)); requests.push_back(json_t::parse(request.substr(split + 4, content_length)));
                for (int elapsed = 0; elapsed < response.delay_ms && !stop.stop_requested(); elapsed += 10) std::this_thread::sleep_for(std::chrono::milliseconds(10));
                const auto body = response.raw.empty() ? dump_json(response.body) : response.raw;
                const auto wire = "HTTP/1.1 " + std::to_string(response.status) + " Fixture\r\nContent-Type: application/json\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                std::size_t sent = 0;
                while (sent < wire.size()) {
                    const int count = send(client.get(), wire.data() + sent, static_cast<int>(wire.size() - sent), 0);
                    if (count <= 0) break; sent += count;
                }
            }
        } catch (...) { error_ = std::current_exception(); }
    });
}
harness::tests::c_http_fixture::~c_http_fixture() { server_.request_stop(); }
std::string harness::tests::c_http_fixture::endpoint(const std::string& path) const { return "http://127.0.0.1:" + std::to_string(port_) + path; }
void harness::tests::c_http_fixture::finish() { server_.join(); if (error_) std::rethrow_exception(error_); }

static harness::json_t final_response(const std::string& provider) {
    if (provider == "openai") return {{"status", "completed"}, {"output", {{{"type", "message"}, {"role", "assistant"}, {"content", {{{"type", "output_text"}, {"text", "Evidence collected; no verified finding."}}}}}}}};
    if (provider == "anthropic") return {{"stop_reason", "end_turn"}, {"content", {{{"type", "text"}, {"text", "Evidence collected; no verified finding."}}}}};
    return {{"done", true}, {"done_reason", "stop"}, {"message", {{"role", "assistant"}, {"content", "Evidence collected; no verified finding."}}}};
}
static harness::json_t calls_response(const std::string& provider, const std::vector<harness::tool_call_t>& calls) {
    harness::json_t items = harness::json_t::array();
    for (const auto& call : calls) {
        if (provider == "openai") items.push_back({{"type", "function_call"}, {"call_id", call.id}, {"name", call.name}, {"arguments", harness::dump_json(call.arguments)}});
        else if (provider == "anthropic") items.push_back({{"type", "tool_use"}, {"id", call.id}, {"name", call.name}, {"input", call.arguments}});
        else items.push_back({{"function", {{"name", call.name}, {"arguments", call.arguments}}}});
    }
    if (provider == "openai") {
        const harness::json_t reasoning = {{"type", "reasoning"}, {"id", "rs_fixture"}, {"summary", harness::json_t::array()}, {"encrypted_content", "opaque-continuation"}};
        items.insert(items.begin(), reasoning);
        return {{"status", "completed"}, {"output", items}};
    }
    if (provider == "anthropic") return {{"stop_reason", "tool_use"}, {"content", items}};
    return {{"done", true}, {"done_reason", "stop"}, {"message", {{"role", "assistant"}, {"content", ""}, {"tool_calls", items}}}};
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    WSADATA sockets{}; if (WSAStartup(MAKEWORD(2, 2), &sockets)) return 2;
    const auto fixture = std::filesystem::absolute(argv[1]);
    const auto root = std::filesystem::current_path() / L"test-data" / harness::widen(harness::new_id());
    std::filesystem::create_directories(root);
    int failures = 0;
    auto test = [&](const std::string& name, auto function) {
        try { function(); std::cout << "PASS " << name << std::endl; }
        catch (const std::exception& error) { ++failures; std::cerr << "FAIL " << name << ": " << error.what() << std::endl; }
    };
    test("files, Unicode, PE validation and bounded reads", [&] {
        auto unicode = root / L"pr\u00edli\u0161 \u017elt\u00fd.bin"; harness::write_text(unicode, "abc");
        std::atomic_bool cancel{false}; harness::limits_t limits;
        auto execute = [&](const std::string& name, harness::json_t args) { return harness::windows::execute_tool(name, args, root, limits, cancel); };
        harness::tests::require(execute("file_sha256", {{"path", harness::path_text(unicode)}}).at("sha256") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 known vector");
        harness::tests::require(execute("file_metadata", {{"path", harness::path_text(unicode)}}).at("size") == 3, "Unicode metadata");
        auto read = execute("file_read", {{"path", harness::path_text(unicode)}, {"length", 2}});
        harness::tests::require(read.at("hex") == "6162" && read.at("truncated") == true, "bounded read");
        harness::tests::require(execute("pe_headers", {{"path", harness::path_text(fixture)}}).at("pe32_plus") == true, "x64 PE headers");
        harness::tests::require(execute("pe_headers", {{"path", harness::path_text(unicode)}}).at("ok") == false, "invalid PE rejected");
        auto truncated = root / L"truncated.exe"; harness::write_text(truncated, std::string("MZ") + std::string(62, '\0'));
        harness::tests::require(execute("pe_headers", {{"path", harness::path_text(truncated)}}).at("ok") == false, "truncated PE rejected");
        harness::tests::require(execute("file_read", {{"path", "x"}, {"offset", -1}}).at("ok") == false, "invalid argument rejected");
        harness::tests::require(execute("invented", harness::json_t::object()).at("ok") == false, "unknown tool rejected");
    });
    test("process arguments, output, nonzero exit, timeout and descendants", [&] {
        std::atomic_bool cancel{false}; harness::limits_t limits; limits.output_limit = 4096;
        auto execute = [&](harness::json_t args) { return harness::windows::execute_tool("process_launch", {{"executable", harness::path_text(fixture)}, {"arguments", args}}, root, limits, cancel); };
        auto echoed = execute({"one two", "quote\"inside", "trailing\\", "", "\u017elt\u00fd"});
        harness::tests::require(echoed.at("ok") == true && echoed.at("stdout") == "one two\nquote\"inside\ntrailing\\\n\n\u017elt\u00fd\n", "argument quoting");
        auto spam = execute({"spam"});
        harness::tests::require(spam.at("ok") == true && spam.at("stdout_truncated") == true && spam.at("stderr_truncated") == true && spam.at("stdout").get<std::string>().size() == 4096, "concurrent bounded output");
        harness::tests::require(execute({"exit"}).at("exit_code") == 7, "nonzero status");
        limits.operation_timeout_ms = 250; auto child = execute({"child"});
        harness::tests::require(child.at("timed_out") == true, "timeout");
        DWORD pid = std::stoul(child.at("stdout").get<std::string>());
        harness::c_handle process(OpenProcess(SYNCHRONIZE, FALSE, pid));
        harness::tests::require(!process.valid() || WaitForSingleObject(process.get(), 2000) == WAIT_OBJECT_0, "descendant terminated");
        limits.operation_timeout_ms = 5000;
        std::jthread trigger([&] { Sleep(100); cancel.store(true); }); auto interrupted = execute({"sleep"});
        harness::tests::require(interrupted.at("cancelled") == true, "explicit cancellation");
    });
    test("both shell backends", [&] {
        std::atomic_bool cancel{false}; harness::limits_t limits;
        for (const auto* shell : {"powershell", "cmd"}) {
            const auto result = harness::windows::execute_tool("shell_execute", {{"shell", shell}, {"command", "echo fixture"}}, root, limits, cancel);
            harness::tests::require(result.at("ok") == true && result.at("stdout").get<std::string>().find("fixture") != std::string::npos, std::string(shell) + " execution");
        }
    });
    test("storage recovery, locking, integrity and unverified summaries", [&] {
        const auto location = root / L"recovery"; std::string id, task;
        {
            harness::storage::c_evidence_store store(location); id = store.create_session(fixture, harness::json_t::object());
            harness::tests::expect_error([&] { harness::storage::c_evidence_store duplicate(location); }, "exclusive lock");
            task = store.append(id, "task", {{"state", "running"}});
            harness::message_t assistant; assistant.role = "assistant"; assistant.calls = {{"pending", "shell_execute", {{"command", "echo should-not-repeat"}}}};
            store.append(id, "message", harness::message_json(assistant));
            store.save_artifact(id, "{\"evidence\":true}");
        }
        {
            harness::storage::c_evidence_store store(location);
            harness::tests::require(store.records(id, "task").front().at("data").at("state") == "interrupted", "unfinished task recovered");
            auto messages = store.records(id, "message");
            harness::tests::require(messages.size() == 2 && messages.back().at("data").at("is_error") == true, "pending model call resolved");
            store.export_session(id, root / L"recovery-export");
            auto artifact = store.records(id, "artifact").front().at("data");
            harness::write_text(location / harness::widen(artifact.at("path")), "tampered");
            harness::tests::expect_error([&] { store.export_session(id, root / L"tampered-export"); }, "artifact integrity verification");
        }
    });
    for (const auto* provider_name : {"openai", "anthropic", "ollama"}) {
        const std::string provider = provider_name;
        test(provider + " HTTP adapter, tool continuation and end-to-end export", [&] {
            std::vector<harness::tool_call_t> calls = {
                {"meta", "file_metadata", {{"path", harness::path_text(fixture)}}},
                {"run", "process_launch", {{"executable", harness::path_text(fixture)}, {"arguments", {"fixture-run"}}}},
                {"shell", "shell_execute", {{"shell", "cmd"}, {"command", "echo fixture-command"}}}
            };
            harness::tests::c_http_fixture server({{200, calls_response(provider, calls), ""}, {200, final_response(provider), ""}});
            SetEnvironmentVariableW(L"GLAIPNIR_TEST_KEY", L"fixture-secret");
            harness::json_t config = {{"profiles", {{"test", {{"provider", provider}, {"model", "fixture-model"}, {"endpoint", server.endpoint()}, {"key_env", "GLAIPNIR_TEST_KEY"}, {"api_key", "must-not-be-saved"}}}}}};
            auto location = root / harness::widen(provider); std::string id;
            {
                harness::storage::c_evidence_store store(location); std::atomic_bool cancel{false}; harness::c_runtime runtime(store, config, cancel);
                id = runtime.create_session(fixture); auto result = runtime.investigate(id, "Inspect this fixture", "test");
                harness::tests::require(result.at("ok") == true && result.at("turns") == 2, "complete investigation: " + harness::dump_json(result));
                harness::tests::require(store.records(id, "task").size() == 3 && store.records(id, "observation").size() == 3, "evidence collected");
                harness::tests::require(store.records(id, "finding").empty() && store.records(id, "summary").front().at("data").at("verified") == false, "no automatic verified finding");
            }
            server.finish();
            harness::tests::require(server.requests.size() == 2, "two HTTP turns");
            harness::tests::require(server.headers.front().find("glAIpnir/" HARNESS_VERSION) != std::string::npos, "versioned HTTP user agent");
            const auto second = harness::dump_json(server.requests.back());
            harness::tests::require(second.find("fixture-command") != std::string::npos && second.find("fixture-run") != std::string::npos, "results returned to model");
            if (provider == "openai") harness::tests::require(second.find("opaque-continuation") != std::string::npos && second.find("function_call_output") != std::string::npos, "reasoning and call outputs preserved");
            if (provider == "anthropic") {
                const auto& messages = server.requests.back().at("messages");
                harness::tests::require(messages.back().at("content").size() == 3 && messages.back().at("content").front().at("type") == "tool_result", "grouped tool results");
                harness::tests::require(server.headers.front().find("x-api-key: fixture-secret") != std::string::npos, "Anthropic auth");
            } else harness::tests::require(server.headers.front().find("Authorization: Bearer fixture-secret") != std::string::npos, "Bearer auth");
            {
                harness::storage::c_evidence_store store(location); auto exported = root / harness::widen(provider + "-export");
                store.export_session(id, exported); const auto history = harness::dump_json(harness::read_json(exported / L"history.json"));
                harness::tests::require(history.find("fixture-secret") == std::string::npos && history.find("must-not-be-saved") == std::string::npos, "credentials excluded");
                harness::tests::require(harness::read_json(exported / L"reproduction.json").at("operations").size() == 3, "reproduction operations");
            }
        });
    }
    test("HTTP retry, malformed response, authentication failure and cancellation", [&] {
        std::atomic_bool cancel{false}; harness::ai::c_winhttp_transport transport;
        harness::tests::c_http_fixture retry({{429, {}, ""}, {503, {}, ""}, {200, {{"ok", true}}, ""}});
        harness::tests::require(transport.post(retry.endpoint(), {}, harness::json_t::object(), 3000, cancel).at("ok") == true, "retry transient status"); retry.finish();
        harness::tests::c_http_fixture malformed({{200, {}, "{invalid"}});
        harness::tests::expect_error([&] { transport.post(malformed.endpoint(), {}, {}, 3000, cancel); }, "malformed response rejected"); malformed.finish();
        harness::tests::c_http_fixture unauthorized({{401, {}, ""}});
        harness::tests::expect_error([&] { transport.post(unauthorized.endpoint(), {}, {}, 3000, cancel); }, "authentication failure is final"); unauthorized.finish();
        harness::tests::c_http_fixture slow({{200, {{"ok", true}}, "", 1000}});
        std::jthread trigger([&] { Sleep(100); cancel.store(true); });
        harness::tests::expect_error([&] { transport.post(slow.endpoint(), {}, {}, 3000, cancel); }, "HTTP cancellation");
    });
    test("model validation, turn limits and failures preserve evidence", [&] {
        auto config = harness::json_t{{"limits", {{"max_turns", 1}}}, {"profiles", {{"test", {{"provider", "ollama"}, {"model", "fixture-model"}, {"key_env", ""}}}}}};
        const std::vector<harness::tool_call_t> calls = {{"call", "file_metadata", {{"path", harness::path_text(fixture)}}}};
        harness::tests::c_http_fixture server({{200, calls_response("ollama", calls), ""}}); config["profiles"]["test"]["endpoint"] = server.endpoint();
        harness::storage::c_evidence_store store(root / L"limits"); std::atomic_bool cancel{false}; harness::c_runtime runtime(store, config, cancel);
        auto id = runtime.create_session(fixture); auto result = runtime.investigate(id, "Inspect", "test");
        harness::tests::require(result.at("ok") == false && store.records(id, "observation").size() == 1 && store.records(id, "investigation_stopped").size() == 1, "turn budget preserves evidence"); server.finish();
        harness::ai::c_model_client client(harness::parse_profile(config, "test"));
        harness::tests::expect_error([&] { client.parse_reply({{"done", false}}); }, "incomplete Ollama rejected");
        harness::tests::expect_error([&] { harness::parse_limits({{"limits", {{"output_limit", 0}}}}); }, "invalid limits rejected");
    });
    WSACleanup(); std::cout << "Failures: " << failures << '\n'; return failures ? 1 : 0;
}
