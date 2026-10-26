#include "harness/storage/store.hpp"
#include "harness/windows/analysis.hpp"
#include <sqlite3.h>
#include <memory>
#include <array>
#include <algorithm>

static std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> prepare(sqlite3* database, const char* sql) {
    sqlite3_stmt* statement{};
    if (sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) throw std::runtime_error(sqlite3_errmsg(database));
    return {statement, sqlite3_finalize};
}
static void bind_text(sqlite3_stmt* statement, int index, const std::string& value) {
    if (sqlite3_bind_text(statement, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
        throw std::runtime_error("SQLite parameter binding failed");
}
static std::string column(sqlite3_stmt* statement, int index) {
    const auto* value = sqlite3_column_text(statement, index);
    return value ? reinterpret_cast<const char*>(value) : "";
}
static void finish(sqlite3* database, sqlite3_stmt* statement) {
    if (sqlite3_step(statement) != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(database));
}
harness::storage::c_evidence_store::c_evidence_store(std::filesystem::path root) : root_(std::filesystem::absolute(root)) {
    std::filesystem::create_directories(root_);
    c_handle lock(CreateFileW((root_ / "runtime.lock").c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    check_win(lock.valid(), "Acquire exclusive store lock (another harness may be running)");
    lock_ = std::move(lock);
    if (sqlite3_open(path_text(root_ / "sessions.sqlite3").c_str(), &database_) != SQLITE_OK) {
        const std::string error = database_ ? sqlite3_errmsg(database_) : "Cannot open database";
        sqlite3_close(database_); database_ = nullptr; throw std::runtime_error(error);
    }
    try {
        execute("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
        auto version = prepare(database_, "PRAGMA user_version");
        if (sqlite3_step(version.get()) != SQLITE_ROW) throw std::runtime_error("Cannot read schema version");
        const int schema = sqlite3_column_int(version.get(), 0);
        version.reset();
        if (schema > 1) throw std::runtime_error("Database was created by a newer harness");
        execute("BEGIN; CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS records(sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,"
            "session_id TEXT NOT NULL REFERENCES sessions(id), kind TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS records_session ON records(session_id,kind); PRAGMA user_version=1; COMMIT;");
        recover();
    } catch (...) { sqlite3_close(database_); database_ = nullptr; throw; }
}
harness::storage::c_evidence_store::~c_evidence_store() { sqlite3_close(database_); }
void harness::storage::c_evidence_store::execute(const char* sql) const {
    char* error{};
    if (sqlite3_exec(database_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        std::string text = error ? error : "SQLite error"; sqlite3_free(error); throw std::runtime_error(text);
    }
}
std::string harness::storage::c_evidence_store::create_session(const std::filesystem::path& target, const harness::json_t& config) {
    return create_session(windows::resolve_target(target_kind_t::file, path_text(target)), config);
}
std::string harness::storage::c_evidence_store::create_session(const harness::research_target_t& target, const harness::json_t& config) {
    const auto info = windows::target_json(target);
    const auto directory = target.kind == target_kind_t::file ? std::filesystem::path(widen(info.at("path"))).parent_path() : std::filesystem::current_path();
    std::string display = info.at("kind");
    if (target.kind == target_kind_t::file) display = info.at("path");
    else if (target.kind == target_kind_t::process) display += ":" + std::to_string(info.at("pid").get<DWORD>());
    else if (target.kind == target_kind_t::service) display += ":" + info.at("name").get<std::string>();
    else if (target.kind == target_kind_t::registry) display += ":" + info.at("key").get<std::string>();
    const auto id = new_id();
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> computer{}; DWORD computer_size = static_cast<DWORD>(computer.size());
    check_win(GetComputerNameW(computer.data(), &computer_size) != FALSE, "GetComputerName");
    using version_function_t = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto get_version = reinterpret_cast<version_function_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    OSVERSIONINFOW version{}; version.dwOSVersionInfoSize = sizeof(version);
    json_t host = {{"computer", narrow(std::wstring(computer.data(), computer_size))}, {"architecture", "x64"}};
    if (get_version && get_version(&version) >= 0) host["windows"] = {{"major", version.dwMajorVersion}, {"minor", version.dwMinorVersion}, {"build", version.dwBuildNumber}};
    json_t data = {{"id", id}, {"target", display}, {"target_info", info},
        {"created", timestamp()}, {"version", HARNESS_VERSION}, {"config", config}, {"working_directory", path_text(directory)},
        {"host", host}};
    if (target.kind == target_kind_t::file) data["target_sha256"] = info.at("sha256");
    auto statement = prepare(database_, "INSERT INTO sessions(id,data) VALUES(?,?)");
    bind_text(statement.get(), 1, id); bind_text(statement.get(), 2, dump_json(data)); finish(database_, statement.get());
    return id;
}
harness::json_t harness::storage::c_evidence_store::list_sessions() const {
    auto statement = prepare(database_, "SELECT data FROM sessions ORDER BY rowid");
    json_t result = json_t::array(); int status{};
    while ((status = sqlite3_step(statement.get())) == SQLITE_ROW) result.push_back(windows::normalize_session(json_t::parse(column(statement.get(), 0))));
    if (status != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(database_));
    return result;
}
harness::json_t harness::storage::c_evidence_store::session(const std::string& id) const {
    auto statement = prepare(database_, "SELECT data FROM sessions WHERE id=?"); bind_text(statement.get(), 1, id);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) throw std::runtime_error("Unknown session: " + id);
    return windows::normalize_session(json_t::parse(column(statement.get(), 0)));
}
harness::json_t harness::storage::c_evidence_store::records(const std::string& session_id, const std::string& kind) const {
    auto statement = prepare(database_, "SELECT id,kind,data,created FROM records WHERE session_id=? AND (?='' OR kind=?) ORDER BY sequence");
    bind_text(statement.get(), 1, session_id); bind_text(statement.get(), 2, kind); bind_text(statement.get(), 3, kind);
    json_t result = json_t::array(); int status{};
    while ((status = sqlite3_step(statement.get())) == SQLITE_ROW)
        result.push_back({{"id", column(statement.get(), 0)}, {"kind", column(statement.get(), 1)},
            {"data", json_t::parse(column(statement.get(), 2))}, {"created", column(statement.get(), 3)}});
    if (status != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(database_));
    return result;
}
std::string harness::storage::c_evidence_store::append(const std::string& session_id, const std::string& kind, const harness::json_t& data) {
    auto statement = prepare(database_, "INSERT INTO records(id,session_id,kind,data,created) VALUES(?,?,?,?,?)");
    auto id = new_id(); bind_text(statement.get(), 1, id); bind_text(statement.get(), 2, session_id); bind_text(statement.get(), 3, kind);
    bind_text(statement.get(), 4, dump_json(data)); bind_text(statement.get(), 5, timestamp()); finish(database_, statement.get()); return id;
}
void harness::storage::c_evidence_store::update_task(const std::string& id, harness::task_state_t state, const harness::json_t& result) {
    auto statement = prepare(database_, "UPDATE records SET data=json_set(data,'$.state',?,'$.updated',?,'$.result',json(?)) WHERE id=? AND kind='task'");
    bind_text(statement.get(), 1, state_text(state)); bind_text(statement.get(), 2, timestamp());
    bind_text(statement.get(), 3, dump_json(result)); bind_text(statement.get(), 4, id); finish(database_, statement.get());
    if (sqlite3_changes(database_) != 1) throw std::runtime_error("Unknown task");
}
harness::json_t harness::storage::c_evidence_store::complete_task(const std::string& session_id, const std::string& task_id,
    harness::task_state_t state, harness::json_t result) {
    execute("BEGIN IMMEDIATE");
    try {
        const auto workspace = root_ / "artifacts" / widen(session_id) / widen(task_id);
        if (std::filesystem::is_directory(workspace)) {
            result["artifact_root"] = path_text(std::filesystem::relative(workspace, root_));
            std::vector<std::filesystem::path> files; std::uintmax_t total = 0;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(workspace)) {
                if (entry.is_symlink() || (GetFileAttributesW(entry.path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)) throw std::runtime_error("Reparse point in research artifacts");
                if (entry.is_regular_file()) { if (files.size() >= 8192) throw std::runtime_error("Research artifact count exceeded"); files.push_back(entry.path()); }
            }
            std::sort(files.begin(), files.end());
            for (const auto& file : files) {
                const auto size = std::filesystem::file_size(file); total += size;
                if (total > 288 * 1024 * 1024) throw std::runtime_error("Research artifact byte limit exceeded");
                append(session_id, "artifact", {{"path", path_text(std::filesystem::relative(file, root_))}, {"sha256", sha256(file)}, {"size", size}, {"task_id", task_id}, {"kind", "research"}});
            }
            result["evidence_file_count"] = files.size(); result["evidence_bytes"] = total;
            for (const auto& file : files) if (file.filename() == L"crash.json") {
                auto record = read_json(file);
                if (!record.contains("signature") || !record.contains("exception_code")) continue;
                const auto relative = path_text(std::filesystem::relative(file, workspace));
                for (const auto& summary : result.value("crashes", json_t::array())) if (summary.value("manifest", "") == relative) record.update(summary);
                record["task_id"] = task_id; record["artifact_root"] = result.at("artifact_root"); record["manifest"] = relative; record["verified_vulnerability"] = false;
                append(session_id, "crash", record);
            }
        }
        const auto artifact = save_artifact(session_id, dump_json(result, 2));
        result["task_id"] = task_id; result["artifact"] = artifact.path;
        append(session_id, "observation", {{"task_id", task_id}, {"data", result}});
        update_task(task_id, state, result);
        execute("COMMIT"); return result;
    } catch (...) { sqlite3_exec(database_, "ROLLBACK", nullptr, nullptr, nullptr); throw; }
}
std::filesystem::path harness::storage::c_evidence_store::task_workspace(const std::string& session_id, const std::string& task_id) {
    session(session_id);
    for (const auto& value : {session_id, task_id}) if (value.empty() || value == "." || value == ".." || value.find_first_of("/\\:") != std::string::npos) throw std::runtime_error("Invalid workspace identifier");
    auto path = root_ / "artifacts" / widen(session_id) / widen(task_id); std::filesystem::create_directories(path); return path;
}
harness::artifact_t harness::storage::c_evidence_store::save_artifact(const std::string& session_id, const std::string& content) {
    session(session_id);
    auto relative = std::filesystem::path("artifacts") / widen(session_id) / widen(new_id() + ".json");
    std::filesystem::create_directories((root_ / relative).parent_path());
    write_text(root_ / relative, content);
    artifact_t artifact{path_text(relative), sha256(root_ / relative), content.size()};
    append(session_id, "artifact", {{"path", artifact.path}, {"sha256", artifact.sha256}, {"size", artifact.size}});
    return artifact;
}
void harness::storage::c_evidence_store::recover() {
    auto pending = prepare(database_, "SELECT id,session_id FROM records WHERE kind='task' AND json_extract(data,'$.state') IN ('queued','running')");
    std::vector<std::pair<std::string, std::string>> interrupted;
    while (sqlite3_step(pending.get()) == SQLITE_ROW) interrupted.emplace_back(column(pending.get(), 0), column(pending.get(), 1));
    pending.reset();
    for (const auto& [task_id, session_id] : interrupted) {
        const auto workspace = root_ / "artifacts" / widen(session_id) / widen(task_id);
        if (!std::filesystem::is_directory(workspace)) continue;
        if (std::filesystem::is_regular_file(workspace / "worker.json")) {
            const auto identity = read_json(workspace / "worker.json");
            c_handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, identity.at("pid").get<DWORD>()));
            if (process.valid() && WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT &&
                windows::process_creation_time(process.get()) == identity.at("creation_time").get<std::string>() && WaitForSingleObject(process.get(), 3000) == WAIT_TIMEOUT)
                throw std::runtime_error("Previous research worker is still exiting; retry opening the store");
        }
        json_t result = {{"ok", false}, {"outcome", "interrupted"}, {"error", "Research worker interrupted; execution was not repeated"}, {"crashes", json_t::array()}};
        for (const auto& entry : std::filesystem::recursive_directory_iterator(workspace)) {
            if (entry.is_symlink() || (GetFileAttributesW(entry.path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)) throw std::runtime_error("Reparse point in interrupted research workspace");
            if (entry.is_regular_file() && entry.path().filename() == L"crash.json") {
            try { auto crash = read_json(entry.path()); if (crash.contains("signature") && crash.contains("exception_code")) result["crashes"].push_back(crash); } catch (const std::exception&) {}
            }
        }
        complete_task(session_id, task_id, task_state_t::interrupted, std::move(result));
    }
    execute("UPDATE records SET data=json_set(data,'$.state','interrupted','$.result',json('{\"ok\":false,\"error\":\"Process interrupted; execution was not repeated\"}')) "
        "WHERE kind='task' AND json_extract(data,'$.state') IN ('queued','running')");
    for (const auto& entry : list_sessions()) {
        const std::string id = entry.at("id");
        std::vector<message_t> messages;
        for (const auto& record : records(id, "message")) messages.push_back(parse_message(record.at("data")));
        for (std::size_t index = 0; index < messages.size(); ++index) {
            for (const auto& call : messages[index].calls) {
                bool resolved = false;
                for (std::size_t later = index + 1; later < messages.size(); ++later)
                    if (messages[later].role == "tool" && messages[later].call_id == call.id) resolved = true;
                if (!resolved) {
                    message_t result; result.role = "tool"; result.call_id = call.id; result.tool_name = call.name; result.is_error = true;
                    result.text = "{\"ok\":false,\"error\":\"Session interrupted before tool result was recorded; command was not repeated\"}";
                    append(id, "message", message_json(result));
                }
            }
        }
    }
}
harness::json_t harness::storage::c_evidence_store::export_session(const std::string& session_id, const std::filesystem::path& destination) const {
    auto data = session(session_id);
    if (std::filesystem::exists(destination)) throw std::runtime_error("Export destination must not exist");
    std::filesystem::create_directories(destination);
    auto history = records(session_id);
    for (const auto& record : history) if (record.at("kind") == "artifact") {
        const auto& artifact = record.at("data");
        auto path = std::filesystem::path(widen(artifact.at("path")));
        if (path.is_absolute() || path.lexically_normal().native().find(L"..") != std::wstring::npos) throw std::runtime_error("Invalid artifact path");
        if (sha256(root_ / path) != artifact.at("sha256").get<std::string>()) throw std::runtime_error("Artifact integrity check failed");
        std::filesystem::create_directories((destination / path).parent_path());
        std::filesystem::copy_file(root_ / path, destination / path);
    }
    write_text(destination / "history.json", dump_json({{"session", data}, {"records", history}}, 2));
    json_t operations = json_t::array();
    for (const auto& record : history) if (record.at("kind") == "task") operations.push_back(record.at("data"));
    json_t manifest = {{"format_version", 1}, {"session", data}, {"operations", operations},
        {"note", "Commands are recorded for explicit reproduction. Export does not execute them. Target binaries are not copied."}};
    write_text(destination / "reproduction.json", dump_json(manifest, 2));
    return {{"destination", path_text(std::filesystem::absolute(destination))}, {"records", history.size()}};
}
