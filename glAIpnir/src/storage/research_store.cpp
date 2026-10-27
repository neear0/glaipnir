#include "harness/storage/store.hpp"
#include <sqlite3.h>
#include <array>
#include <fstream>
#include <map>
#include <set>
#include <functional>
#include <memory>
#include <algorithm>

static std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(sqlite3* database, const char* sql) {
    sqlite3_stmt* value{};
    if (sqlite3_prepare_v2(database, sql, -1, &value, nullptr) != SQLITE_OK) throw std::runtime_error(sqlite3_errmsg(database));
    return {value, sqlite3_finalize};
}
static void bind(sqlite3_stmt* value, int index, const std::string& text) {
    if (sqlite3_bind_text(value, index, text.data(), static_cast<int>(text.size()), SQLITE_TRANSIENT) != SQLITE_OK) throw std::runtime_error("SQLite binding failed");
}
static void check_cancelled(const std::atomic_bool& cancelled) {
    if (cancelled.load()) throw std::runtime_error("Cancelled");
}
harness::json_t harness::storage::c_evidence_store::record(const std::string& session_id, const std::string& id) const {
    auto query = statement(database_, "SELECT kind,data,created FROM records WHERE session_id=? AND id=?");
    bind(query.get(), 1, session_id); bind(query.get(), 2, id);
    if (sqlite3_step(query.get()) != SQLITE_ROW) throw std::runtime_error("Unknown record in this session: " + id);
    auto text = [&](int column) { return std::string(reinterpret_cast<const char*>(sqlite3_column_text(query.get(), column))); };
    return {{"id", id}, {"kind", text(0)}, {"data", json_t::parse(text(1))}, {"created", text(2)}};
}
harness::json_t harness::storage::c_evidence_store::begin_experiment(const std::string& session_id, harness::json_t experiment, harness::json_t task) {
    session(session_id); execute("BEGIN IMMEDIATE");
    try {
        const auto experiment_id = new_id(), task_id = new_id();
        experiment["task_id"] = task_id; experiment["state"] = "queued"; experiment["verified"] = false;
        task["experiment_id"] = experiment_id; task["state"] = "queued";
        append(session_id, "experiment", experiment, experiment_id); append(session_id, "task", task, task_id);
        execute("COMMIT"); return {{"experiment_id", experiment_id}, {"task_id", task_id}};
    } catch (...) { sqlite3_exec(database_, "ROLLBACK", nullptr, nullptr, nullptr); throw; }
}
std::filesystem::path harness::storage::c_evidence_store::artifact_path(const std::string& relative) const {
    const auto path = std::filesystem::path(widen(relative));
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory()) throw std::runtime_error("Artifact path must be relative");
    auto resolved = root_;
    for (const auto& part : path) {
        if (part == L".." || part == L".") throw std::runtime_error("Invalid artifact path component");
        resolved /= part;
        const auto attributes = GetFileAttributesW(extended_path(resolved).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) throw std::runtime_error("Missing artifact or reparse point in evidence path");
    }
    if (!std::filesystem::is_regular_file(extended_path(resolved))) throw std::runtime_error("Artifact is not a regular file");
    return extended_path(resolved);
}
harness::json_t harness::storage::c_evidence_store::read_evidence(const std::string& session_id, const std::string& artifact_id,
    std::uint64_t offset, std::size_t length, const std::atomic_bool& cancelled) const {
    if (length < 1 || length > 65536) throw std::runtime_error("Evidence reads require 1..65536 bytes");
    const auto artifact = record(session_id, artifact_id);
    if (artifact.at("kind") != "artifact") throw std::runtime_error("Expected an artifact record");
    const auto& data = artifact.at("data"); const auto path = artifact_path(data.at("path"));
    check_cancelled(cancelled);
    const auto size = std::filesystem::file_size(path);
    if (size != data.at("size").get<std::uintmax_t>() || sha256(path, &cancelled) != data.at("sha256").get<std::string>()) throw std::runtime_error("Artifact integrity check failed");
    if (offset > size) throw std::runtime_error("Evidence offset exceeds file size");
    const auto count = static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(length), size - offset));
    std::ifstream stream(path, std::ios::binary); stream.seekg(static_cast<std::streamoff>(offset));
    std::string bytes(count, '\0'); stream.read(bytes.data(), static_cast<std::streamsize>(count));
    if (!stream) throw std::runtime_error("Cannot read evidence");
    check_cancelled(cancelled);
    if (sha256(path, &cancelled) != data.at("sha256").get<std::string>()) throw std::runtime_error("Artifact changed during evidence read");
    constexpr char digits[] = "0123456789abcdef"; std::string hex; hex.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) { hex += digits[byte >> 4]; hex += digits[byte & 15]; }
    return {{"ok", true}, {"artifact_id", artifact_id}, {"offset", offset}, {"size", size}, {"bytes_read", count},
        {"sha256", data.at("sha256")}, {"hex", hex}, {"text", bytes}, {"truncated", offset + count < size}};
}
static bool reference_key(const std::string& key) {
    return key == "id" || key.ends_with("_id") || key.ends_with("_ids") || key == "records";
}
static void visit_references(const harness::json_t& value, const std::string& key, const std::function<void(const std::string&, const std::string&)>& visit) {
    if (value.is_object()) {
        for (const auto& [name, child] : value.items()) if (name != "origin") visit_references(child, name, visit);
    } else if (value.is_array()) {
        for (const auto& child : value) visit_references(child, key, visit);
    } else if (value.is_string() && reference_key(key)) visit(value.get<std::string>(), key);
}
static void rewrite_snapshot(harness::json_t& value, const std::string& key, const std::map<std::string, std::string>& ids,
    const std::string& old_prefix, const std::string& new_prefix) {
    if (value.is_object()) {
        for (auto& [name, child] : value.items()) if (name != "origin") rewrite_snapshot(child, name, ids, old_prefix, new_prefix);
    } else if (value.is_array()) {
        for (auto& child : value) rewrite_snapshot(child, key, ids, old_prefix, new_prefix);
    } else if (value.is_string()) {
        const auto text = value.get<std::string>();
        if (reference_key(key) && ids.contains(text)) value = ids.at(text);
        else if (text.starts_with(old_prefix)) value = new_prefix + text.substr(old_prefix.size());
    }
}
harness::json_t harness::storage::c_evidence_store::import_research(const std::string& destination, const std::string& source,
    const harness::json_t& ids, const std::atomic_bool& cancelled) {
    const auto source_session = session(source), destination_session = session(destination);
    if (source == destination) throw std::runtime_error("Source and destination sessions must differ");
    if (!ids.is_array() || ids.empty() || ids.size() > 100) throw std::runtime_error("Select 1..100 research records");
    const std::set<std::string> kinds = {"hypothesis", "experiment", "assessment", "observation", "task", "artifact", "crash", "context_import"};
    std::map<std::string, json_t> index; std::map<std::string, std::string> artifact_ids; std::vector<std::string> source_order;
    for (const auto& item : records(source)) if (kinds.contains(item.at("kind").get<std::string>())) {
        index.emplace(item.at("id").get<std::string>(), item);
        source_order.push_back(item.at("id"));
        if (item.at("kind") == "artifact") artifact_ids.emplace(item.at("data").at("path").get<std::string>(), item.at("id").get<std::string>());
    }
    std::set<std::string> selected; std::vector<std::string> pending;
    auto select = [&](const std::string& id) {
        if (!index.contains(id)) throw std::runtime_error("Unknown or unsupported source record: " + id);
        if (selected.insert(id).second) { if (selected.size() > 4096) throw std::runtime_error("Import dependency limit exceeded"); pending.push_back(id); }
    };
    for (const auto& id : ids) select(id.get<std::string>());
    for (std::size_t position = 0; position < pending.size(); ++position) {
        check_cancelled(cancelled); const auto id = pending[position]; const auto& item = index.at(id); const auto& data = item.at("data");
        if ((item.at("kind") == "task" || item.at("kind") == "experiment") && (data.value("state", "") == "queued" || data.value("state", "") == "running"))
            throw std::runtime_error("Cannot snapshot unfinished research");
        visit_references(data, "", [&](const std::string& reference, const std::string& key) {
            static const std::set<std::string> dependencies = {"hypothesis_id", "observation_id", "observation_ids", "experiment_id", "experiment_ids", "task_id", "artifact_id", "record_ids"};
            if (index.contains(reference)) select(reference);
            else if (dependencies.contains(key) && !reference.empty()) throw std::runtime_error("Missing research dependency: " + reference);
        });
        if (data.contains("artifact") && data.at("artifact").is_string() && artifact_ids.contains(data.at("artifact").get<std::string>())) select(artifact_ids.at(data.at("artifact").get<std::string>()));
        if (data.contains("result") && data.at("result").is_object() && data.at("result").contains("artifact")) {
            const auto path = data.at("result").at("artifact").get<std::string>(); if (artifact_ids.contains(path)) select(artifact_ids.at(path));
        }
        for (const auto& [other_id, other] : index) {
            const auto& other_data = other.at("data");
            if ((item.at("kind") == "hypothesis" && other_data.value("hypothesis_id", "") == id) ||
                (item.at("kind") == "task" && other_data.value("task_id", "") == id) ||
                (item.at("kind") == "experiment" && other_data.value("experiment_id", "") == id)) select(other_id);
        }
    }
    check_cancelled(cancelled);
    const auto task = append(destination, "task", {{"state", "running"}, {"tool", "context_import"}, {"source_session_id", source}, {"selected_source_record_ids", ids}});
    const auto workspace = task_workspace(destination, task);
    const auto source_base = std::filesystem::path("artifacts") / widen(source);
    const auto destination_base = std::filesystem::path("artifacts") / widen(destination) / widen(task) / L"evidence";
    const auto old_prefix = path_text(source_base) + "\\", new_prefix = path_text(destination_base) + "\\";
    std::map<std::string, std::string> mapped; for (const auto& id : selected) mapped[id] = new_id();
    bool transaction = false;
    try {
        std::uintmax_t total = 0; std::size_t files = 0;
        for (const auto& id : selected) if (index.at(id).at("kind") == "artifact") {
            check_cancelled(cancelled); const auto& data = index.at(id).at("data");
            const auto relative = std::filesystem::path(widen(data.at("path"))).lexically_relative(source_base);
            if (relative.empty() || *relative.begin() == L"..") throw std::runtime_error("Source artifact is outside its session");
            const auto original = artifact_path(data.at("path")); const auto size = std::filesystem::file_size(original); total += size;
            if (++files > 8192 || total > 288 * 1024 * 1024) throw std::runtime_error("Import artifact limit exceeded");
            if (size != data.at("size").get<std::uintmax_t>() || sha256(original, &cancelled) != data.at("sha256").get<std::string>()) throw std::runtime_error("Source artifact integrity check failed");
            const auto copied = extended_path(root_ / destination_base / relative); std::filesystem::create_directories(copied.parent_path());
            std::ifstream input(original, std::ios::binary); std::ofstream output(copied, std::ios::binary); std::array<char, 65536> buffer{};
            if (!input || !output) throw std::runtime_error("Cannot open import evidence");
            while (input) { check_cancelled(cancelled); input.read(buffer.data(), buffer.size()); output.write(buffer.data(), input.gcount()); if (!output) throw std::runtime_error("Cannot copy import evidence"); }
            if (!input.eof()) throw std::runtime_error("Cannot read source evidence");
            output.close(); if (!output || sha256(copied, &cancelled) != data.at("sha256").get<std::string>()) throw std::runtime_error("Copied artifact integrity check failed");
        }
        check_cancelled(cancelled);
        const auto& from = source_session.at("target_info"); const auto& to = destination_session.at("target_info");
        const bool same_target = from.at("kind") == "file" && to.at("kind") == "file" ? from.at("sha256") == to.at("sha256") :
            from == to && source_session.at("host").value("computer", "") == destination_session.at("host").value("computer", "");
        execute("BEGIN IMMEDIATE"); transaction = true; json_t imported = json_t::array();
        for (const auto& id : source_order) if (selected.contains(id)) {
            check_cancelled(cancelled); auto data = index.at(id).at("data"); const auto previous = data.value("origin", json_t(nullptr));
            rewrite_snapshot(data, "", mapped, old_prefix, new_prefix);
            data["origin"] = {{"session_id", source}, {"record_id", id}, {"created", index.at(id).at("created")}, {"target", from}, {"previous", previous}};
            const bool inherited_background = data.value("background", false) || (index.at(id).at("kind") == "context_import" && !data.value("same_target", true));
            data["imported"] = true; data["background"] = !same_target || inherited_background; data["verified"] = false; data["verified_vulnerability"] = false;
            append(destination, index.at(id).at("kind"), data, mapped.at(id)); imported.push_back(mapped.at(id));
        }
        const auto import_id = append(destination, "context_import", {{"source_session_id", source}, {"source_target", from}, {"same_target", same_target},
            {"selected_record_ids", ids}, {"record_ids", imported}, {"task_id", task}, {"verified", false}});
        auto result = complete_task(destination, task, task_state_t::succeeded, {{"ok", true}, {"imported_context", true}, {"import_id", import_id},
            {"record_ids", imported}, {"artifact_root", path_text(std::filesystem::relative(workspace, root_))}, {"evidence_file_count", files}, {"evidence_bytes", total}}, false);
        execute("COMMIT"); transaction = false; return result;
    } catch (const std::exception& error) {
        if (transaction) sqlite3_exec(database_, "ROLLBACK", nullptr, nullptr, nullptr);
        return complete_task(destination, task, cancelled.load() ? task_state_t::cancelled : task_state_t::failed,
            {{"ok", false}, {"cancelled", cancelled.load()}, {"imported_context", true}, {"error", error.what()}});
    }
}
