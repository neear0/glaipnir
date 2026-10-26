#include "windows_support.hpp"
#include <sqlite3.h>
#include <array>
#include <cstring>

static harness::windows::local_memory_t descriptor(const wchar_t* text) {
    PSECURITY_DESCRIPTOR value{};
    harness::windows::require_win(ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &value, nullptr), "Parse test descriptor");
    return harness::windows::local_memory_t(value);
}
static bool privilege_enabled(HANDLE token, const wchar_t* name) {
    LUID luid{}; harness::windows::require_win(LookupPrivilegeValueW(nullptr, name, &luid), "Lookup fixture privilege");
    auto bytes = harness::windows::token_data(token, TokenPrivileges); auto info = reinterpret_cast<TOKEN_PRIVILEGES*>(bytes.data());
    for (DWORD index = 0; index < info->PrivilegeCount; ++index) if (info->Privileges[index].Luid.HighPart == luid.HighPart && info->Privileges[index].Luid.LowPart == luid.LowPart)
        return (info->Privileges[index].Attributes & SE_PRIVILEGE_ENABLED) != 0;
    return false;
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    const auto fixture = std::filesystem::absolute(argv[1]);
    const auto root = std::filesystem::current_path() / L"windows-test-data" / harness::widen(harness::new_id());
    std::filesystem::create_directories(root); std::atomic_bool cancelled{false}; harness::limits_t limits;
    int failures = 0;
    auto test = [&](const char* name, auto function) {
        try { function(); std::cout << "PASS " << name << std::endl; }
        catch (const std::exception& error) { ++failures; std::cerr << "FAIL " << name << ": " << error.what() << std::endl; }
    };
    auto execute = [&](const std::string& name, const harness::json_t& args) {
        return harness::windows::execute_tool(name, args, root, limits, cancelled);
    };
    test("process identities, modules, threads, token and errors", [&] {
        harness::tests::c_process_fixture child(fixture);
        const auto pid = child.pid();
        auto info = execute("process_info", {{"pid", pid}});
        harness::tests::check(info.at("ok") == true && info.at("path").get<std::string>().find("harness_fixture") != std::string::npos, "owned process details: " + harness::dump_json(info));
        auto identity = harness::json_t{{"pid", pid}, {"creation_time", info.at("creation_time")}};
        // Allow the new fixture to complete loader initialization before enumerating modules.
        Sleep(100);
        auto modules = execute("process_modules", identity); auto threads = execute("process_threads", identity);
        harness::tests::check(modules.at("ok") == true && !modules.at("items").empty(), "module list: " + harness::dump_json(modules));
        harness::tests::check(threads.at("ok") == true && !threads.at("items").empty(), "thread list");
        auto token = execute("token_info", identity);
        harness::tests::check(token.at("ok") == true && token.contains("user") && token.contains("integrity") && token.contains("privileges"), "process token");
        auto process_security = execute("security_descriptor", {{"target", {{"kind", "process"}, {"pid", pid}, {"creation_time", info.at("creation_time")}}}});
        harness::tests::check(process_security.at("ok") == true && process_security.contains("aces"), "process security descriptor");
        const auto token_file = root / L"selected-token.txt"; harness::write_text(token_file, "fixture");
        auto selected_check = execute("security_access_check", {{"target", {{"kind", "file"}, {"path", harness::path_text(token_file)}}},
            {"access_mask", FILE_READ_DATA}, {"token_pid", pid}, {"token_creation_time", info.at("creation_time")}});
        harness::tests::check(selected_check.at("ok") == true && selected_check.at("access_allowed") == true &&
            selected_check.at("token_creation_time") == info.at("creation_time"), "selected process token access check");
        identity["creation_time"] = "0";
        harness::tests::check(execute("process_info", identity).at("error_code") == ERROR_INVALID_PARAMETER, "PID reuse prevention");
        auto error = execute("process_info", {{"pid", 0xffffffffULL}});
        harness::tests::check(error.at("ok") == false && error.contains("operation") && error.contains("error_code"), "invalid process native error");
        TerminateProcess(child.handle(), 0); WaitForSingleObject(child.handle(), 2000);
        harness::tests::check(execute("process_info", {{"pid", pid}}).at("ok") == false, "exited process rejected");
    });
    test("bounded live enumeration, validation and cancellation", [&] {
        auto first = execute("process_list", {{"limit", 1}});
        harness::tests::check(first.at("items").size() == 1 && !first.at("next_offset").is_null() && first.at("truncated") == true, "process pagination");
        auto second = execute("process_list", {{"offset", first.at("next_offset")}, {"limit", 1}});
        harness::tests::check(second.at("items").size() == 1, "process continuation");
        for (const auto& invalid : std::vector<harness::json_t>{{{"limit", 0}}, {{"limit", 4097}}, {{"offset", -1}}, {{"limit", true}}})
            harness::tests::check(execute("process_list", invalid).at("ok") == false, "invalid page rejected");
        harness::tests::check(execute("process_info", {{"pid", 0x100000000ULL}}).at("ok") == false, "PID overflow rejected");
        harness::tests::check(execute("security_descriptor", {{"target", {{"kind", "file"}, {"pid", 1}}}}).at("ok") == false, "nested selector validation");
        auto before = limits.output_limit; limits.output_limit = 32;
        harness::tests::check(execute("process_list", harness::json_t::object()).at("error_code") == ERROR_INSUFFICIENT_BUFFER, "output budget enforced");
        limits.output_limit = before; cancelled.store(true);
        harness::tests::check(execute("process_list", harness::json_t::object()).at("cancelled") == true, "analysis cancellation"); cancelled.store(false);
    });
    test("registry types, views, Unicode, default value and malformed data", [&] {
        harness::tests::c_registry_fixture key;
        const wchar_t text[] = L"\u017elt\u00fd"; const wchar_t expandable[] = L"%TEMP%\\fixture"; const wchar_t multi[] = L"one\0two\0";
        DWORD integer = 42; std::uint64_t wide = 0x123456789abcdef0ULL; const unsigned char binary[] = {0, 255, 128};
        key.set(L"", REG_SZ, text, sizeof(text)); key.set(L"expand", REG_EXPAND_SZ, expandable, sizeof(expandable));
        key.set(L"multi", REG_MULTI_SZ, multi, sizeof(multi)); key.set(L"number", REG_DWORD, &integer, sizeof(integer));
        key.set(L"wide", REG_QWORD, &wide, sizeof(wide)); key.set(L"binary", REG_BINARY, binary, sizeof(binary));
        key.set(L"bad", REG_DWORD, binary, sizeof(binary));
        auto read = [&](const char* name) { return execute("registry_read", {{"key", key.path()}, {"name", name}}); };
        harness::tests::check(read("").at("data") == "\u017elt\u00fd", "default Unicode string");
        harness::tests::check(read("expand").at("data") == "%TEMP%\\fixture" && read("expand").at("expanded") == false, "no environment expansion");
        harness::tests::check(read("multi").at("data").size() == 2, "multi string");
        harness::tests::check(read("number").at("data") == 42 && read("wide").at("data") == wide, "integer decoding");
        harness::tests::check(read("binary").at("hex") == "00ff80" && read("bad").at("malformed") == true, "raw and malformed values");
        harness::tests::check(read("missing").at("error_code") == ERROR_FILE_NOT_FOUND, "missing value");
        auto entries = execute("registry_list", {{"key", key.path()}, {"limit", 2}});
        harness::tests::check(entries.at("items").size() == 2 && entries.at("truncated") == true, "registry pagination");
        for (const auto* view : {"32", "64"}) {
            auto result = execute("registry_list", {{"key", key.path()}, {"view", view}});
            harness::tests::check(result.at("ok") == true && result.at("view") == view, "explicit registry view");
        }
        auto security = execute("security_descriptor", {{"target", {{"kind", "registry"}, {"key", key.path()}}}});
        harness::tests::check(security.at("ok") == true && security.contains("owner"), "registry security descriptor");
        harness::tests::check(harness::windows::decode_registry_value(REG_SZ, {65}).at("malformed") == true, "odd UTF-16 length");
        harness::tests::check(harness::windows::decode_registry_value(REG_MULTI_SZ, {65, 0}).at("malformed") == true, "unterminated multi string");
    });
    test("service decoding and read-only native inspection", [&] {
        wchar_t dependencies[] = L"first\0+group\0"; wchar_t binary[] = L"C:\\fixture.exe --service"; wchar_t account[] = L"LocalSystem";
        QUERY_SERVICE_CONFIGW config{}; config.dwServiceType = SERVICE_WIN32_OWN_PROCESS; config.dwStartType = SERVICE_DEMAND_START;
        config.lpDependencies = dependencies; config.lpBinaryPathName = binary; config.lpServiceStartName = account;
        auto decoded = harness::windows::decode_service_config(config);
        harness::tests::check(decoded.at("dependencies").size() == 2 && decoded.at("account") == "LocalSystem", "service config decoding");
        auto services = execute("service_list", {{"limit", 4096}});
        harness::tests::check(services.at("ok") == true && !services.at("items").empty(), "local services");
        auto info = execute("service_info", {{"name", "EventLog"}});
        harness::tests::check(info.at("ok") == true && info.contains("binary_path") && info.contains("account"), "EventLog service inspection: " + harness::dump_json(info));
        auto security = execute("security_descriptor", {{"target", {{"kind", "service"}, {"name", "EventLog"}}}});
        harness::tests::check(security.at("ok") == true || security.value("error_code", 0) == ERROR_ACCESS_DENIED, "service descriptor or explicit denial");
    });
    test("descriptor semantics, access masks and unsupported ACEs", [&] {
        auto token = harness::windows::open_token(harness::json_t::object(), TOKEN_QUERY | TOKEN_DUPLICATE);
        const GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
        auto allow = descriptor(L"O:SYG:SYD:(A;;FA;;;WD)"); auto deny = descriptor(L"O:SYG:SYD:(D;;0x1;;;WD)(A;;FA;;;WD)");
        auto empty = descriptor(L"O:SYG:SYD:"); auto absent = descriptor(L"O:SYG:SY"); auto null_acl = descriptor(L"O:SYG:SYD:NO_ACCESS_CONTROL");
        for (const auto& [memory, expected] : std::array<std::pair<void*, const char*>, 3>{{{empty.get(), "empty"}, {absent.get(), "absent"}, {null_acl.get(), "null"}}})
            harness::tests::check(harness::windows::decode_descriptor(memory).at("dacl_state") == expected, "DACL classification");
        auto checked = harness::windows::check_descriptor_access(allow.get(), token.get(), GENERIC_READ, mapping);
        harness::tests::check(checked.at("access_allowed") == true && checked.at("mapped_mask") == FILE_GENERIC_READ && checked.at("actual_open_guaranteed") == false, "mapped generic access");
        harness::tests::check(harness::windows::check_descriptor_access(deny.get(), token.get(), FILE_READ_DATA, mapping).at("access_allowed") == false, "deny ACE");
        harness::tests::check(harness::windows::check_descriptor_access(empty.get(), token.get(), FILE_READ_DATA, mapping).at("access_allowed") == false, "empty ACL denies");
        harness::tests::check(harness::windows::check_descriptor_access(null_acl.get(), token.get(), FILE_READ_DATA, mapping).at("access_allowed") == true, "null ACL grants");
        auto inherited = descriptor(L"O:SYG:SYD:(A;ID;0x1;;;WD)");
        harness::tests::check(harness::windows::decode_descriptor(inherited.get()).at("aces").front().at("inherited") == true, "inherited ACE retained");
        alignas(ACL) std::array<unsigned char, 256> acl_bytes{}; auto acl = reinterpret_cast<ACL*>(acl_bytes.data());
        harness::windows::require_win(InitializeAcl(acl, static_cast<DWORD>(acl_bytes.size()), ACL_REVISION_DS), "InitializeAcl fixture");
        alignas(ACE_HEADER) std::array<unsigned char, 20> ace{}; auto header = reinterpret_cast<ACE_HEADER*>(ace.data()); header->AceType = ACCESS_ALLOWED_CALLBACK_ACE_TYPE; header->AceSize = static_cast<WORD>(ace.size());
        DWORD mask = FILE_READ_DATA; std::memcpy(ace.data() + 4, &mask, sizeof(mask)); DWORD sid_size = 12;
        harness::windows::require_win(CreateWellKnownSid(WinWorldSid, nullptr, ace.data() + 8, &sid_size), "CreateWellKnownSid fixture");
        harness::windows::require_win(AddAce(acl, ACL_REVISION_DS, MAXDWORD, ace.data(), static_cast<DWORD>(ace.size())), "AddAce fixture");
        SECURITY_DESCRIPTOR unsupported{}; InitializeSecurityDescriptor(&unsupported, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&unsupported, TRUE, acl, FALSE);
        harness::tests::fails([&] { harness::windows::check_descriptor_access(&unsupported, token.get(), FILE_READ_DATA, mapping); }, "unsupported callback ACE rejected");
        auto file = root / L"security.txt"; harness::write_text(file, "fixture");
        auto live = execute("security_access_check", {{"target", {{"kind", "file"}, {"path", harness::path_text(file)}}}, {"access_mask", FILE_READ_DATA}});
        harness::tests::check(live.at("ok") == true && live.at("access_allowed") == true, "live file descriptor access check: " + harness::dump_json(live));
    });
    test("privilege opt-in, unavailable privilege and restoration", [&] {
        auto original = harness::windows::open_token(harness::json_t::object(), TOKEN_QUERY | TOKEN_DUPLICATE); HANDLE raw{};
        harness::windows::require_win(DuplicateTokenEx(original.get(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, nullptr, SecurityImpersonation, TokenPrimary, &raw), "Duplicate privilege fixture");
        harness::c_handle token(raw); TOKEN_PRIVILEGES change{}; change.PrivilegeCount = 1;
        LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &change.Privileges[0].Luid); change.Privileges[0].Attributes = 0;
        harness::windows::require_win(AdjustTokenPrivileges(token.get(), FALSE, &change, 0, nullptr, nullptr), "Disable fixture privilege");
        harness::tests::check(!privilege_enabled(token.get(), SE_CHANGE_NOTIFY_NAME), "fixture starts disabled");
        { harness::windows::c_privilege_scope scope(true, token.get(), SE_CHANGE_NOTIFY_NAME); harness::tests::check(privilege_enabled(token.get(), SE_CHANGE_NOTIFY_NAME), "held privilege enabled"); }
        harness::tests::check(!privilege_enabled(token.get(), SE_CHANGE_NOTIFY_NAME), "previous state restored");
        LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &change.Privileges[0].Luid); change.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        AdjustTokenPrivileges(token.get(), FALSE, &change, 0, nullptr, nullptr);
        harness::tests::fails([&] { harness::windows::c_privilege_scope unavailable(true, token.get()); }, "unavailable debug privilege fails");
        { harness::windows::c_privilege_scope unchanged(false, token.get()); }
        harness::tests::check(!privilege_enabled(token.get(), SE_CHANGE_NOTIFY_NAME), "default leaves privileges unchanged");
    });
    test("typed sessions, process binding, model tools, restart and export", [&] {
        harness::tests::c_registry_fixture registry; harness::tests::c_process_fixture process(fixture);
        const auto location = root / L"sessions"; std::string process_id;
        harness::json_t config = {{"profiles", {{"test", {{"provider", "ollama"}, {"model", "fixture"}, {"key_env", ""}}}}}};
        {
            harness::storage::c_evidence_store store(location); harness::c_runtime runtime(store, config, cancelled);
            std::vector<harness::research_target_t> targets = {
                harness::windows::resolve_target(harness::target_kind_t::file, harness::path_text(fixture)),
                harness::windows::resolve_target(harness::target_kind_t::process, std::to_string(process.pid())),
                harness::windows::resolve_target(harness::target_kind_t::service, "EventLog"),
                harness::windows::resolve_target(harness::target_kind_t::registry, registry.path()),
                harness::windows::resolve_target(harness::target_kind_t::machine, "")
            };
            for (const auto& target : targets) {
                auto id = runtime.create_session(target); auto session = store.session(id);
                harness::tests::check(session.at("target_info") == target.identity && session.at("version") == HARNESS_VERSION, "typed target persisted");
                if (target.kind != harness::target_kind_t::file) harness::tests::check(!session.contains("target_sha256"), "non-file session needs no hash");
                std::string native_tool; harness::json_t native_args;
                if (target.kind == harness::target_kind_t::file) { native_tool = "file_metadata"; native_args = {{"path", target.identity.at("path")}}; }
                else if (target.kind == harness::target_kind_t::process) { native_tool = "process_info"; native_args = {{"pid", process.pid()}}; }
                else if (target.kind == harness::target_kind_t::service) { native_tool = "service_info"; native_args = {{"name", "EventLog"}}; }
                else if (target.kind == harness::target_kind_t::registry) { native_tool = "registry_list"; native_args = {{"key", registry.path()}}; }
                else { native_tool = "process_list"; native_args = {{"limit", 2}}; }
                auto model = std::make_shared<harness::tests::c_script_model>(std::vector<harness::tool_call_t>{{"inspect", native_tool, native_args}});
                auto result = runtime.investigate(id, "Inspect token and summarize", "test", model);
                harness::tests::check(result.at("ok") == true && store.records(id, "observation").size() == 1, "typed investigation");
                harness::tests::check(store.records(id, "observation").front().at("data").at("data").at("ok") == true, "native target observation succeeded");
                store.export_session(id, root / harness::widen("export-" + id));
                if (target.kind == harness::target_kind_t::process) {
                    process_id = id;
                    auto detail = runtime.dispatch(id, "process_info", {{"pid", process.pid()}});
                    harness::tests::check(detail.at("ok") == true, "bound process inspection");
                    auto tasks = store.records(id, "task");
                    harness::tests::check(tasks.back().at("data").at("arguments").contains("creation_time"), "identity automatically bound");
                    harness::tests::check(runtime.dispatch(id, "process_info", {{"pid", process.pid()}, {"creation_time", "0"}}).at("ok") == false, "identity override rejected");
                }
            }
        }
        TerminateProcess(process.handle(), 0); WaitForSingleObject(process.handle(), 2000);
        harness::storage::c_evidence_store store(location); harness::c_runtime runtime(store, config, cancelled);
        harness::tests::check(store.list_sessions().size() == 5, "all targets reopen");
        harness::tests::check(runtime.dispatch(process_id, "process_info", {{"pid", process.pid()}}).at("ok") == false, "exited target after restart");
    });
    test("legacy session normalization preserves original database records", [&] {
        const auto location = root / L"legacy"; std::filesystem::create_directories(location);
        sqlite3* database{}; harness::tests::check(sqlite3_open(harness::path_text(location / L"sessions.sqlite3").c_str(), &database) == SQLITE_OK, "legacy database open");
        sqlite3_exec(database, "CREATE TABLE sessions(id TEXT PRIMARY KEY,data TEXT NOT NULL); PRAGMA user_version=1", nullptr, nullptr, nullptr);
        harness::json_t legacy = {{"id", "legacy"}, {"target", harness::path_text(fixture)}, {"target_sha256", "original-hash"},
            {"version", "0.1.0"}, {"working_directory", harness::path_text(root)}, {"config", harness::json_t::object()}};
        sqlite3_stmt* statement{}; sqlite3_prepare_v2(database, "INSERT INTO sessions VALUES('legacy',?)", -1, &statement, nullptr);
        auto text = harness::dump_json(legacy); sqlite3_bind_text(statement, 1, text.c_str(), -1, SQLITE_TRANSIENT); sqlite3_step(statement); sqlite3_finalize(statement); sqlite3_close(database);
        {
            harness::storage::c_evidence_store store(location); auto session = store.session("legacy");
            harness::tests::check(session.at("version") == "0.1.0" && session.at("target_info").at("kind") == "file" && session.at("target_sha256") == "original-hash", "legacy interpretation and provenance");
            harness::c_runtime runtime(store, harness::json_t::object(), cancelled);
            harness::tests::check(runtime.dispatch("legacy", "file_metadata", {{"path", harness::path_text(fixture)}}).at("ok") == true, "legacy tools remain usable");
        }
        sqlite3_open(harness::path_text(location / L"sessions.sqlite3").c_str(), &database);
        sqlite3_prepare_v2(database, "SELECT data FROM sessions WHERE id='legacy'", -1, &statement, nullptr); sqlite3_step(statement);
        auto unchanged = harness::json_t::parse(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)));
        sqlite3_finalize(statement); sqlite3_close(database); harness::tests::check(unchanged == legacy, "legacy record not rewritten");
    });
    std::cout << "Failures: " << failures << '\n'; return failures ? 1 : 0;
}
