#include "harness/research/backend.hpp"
#include <bcrypt.h>
#include <fstream>
#include <iomanip>
#include <sstream>

std::filesystem::path harness::research::c_context::path(const std::filesystem::path& relative) const {
    if (relative.is_absolute() || relative.has_root_name()) throw std::runtime_error("Research artifact path must be relative");
    for (const auto& part : relative) if (part == L"..") throw std::runtime_error("Research artifact escapes workspace");
    auto result = workspace / relative;
    std::filesystem::create_directories(result.parent_path()); return result;
}
std::uintmax_t harness::research::c_context::remaining() const {
    std::uintmax_t used = 0; std::size_t count = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(workspace)) {
        if (++count > 8192) throw std::runtime_error("Research artifact count limit reached");
        if (entry.is_symlink() || (GetFileAttributesW(entry.path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)) throw std::runtime_error("Research workspace contains a reparse point");
        if (entry.is_regular_file()) { used += entry.file_size(); if (used >= artifact_limit) return 0; }
    }
    return artifact_limit - used;
}
void harness::research::c_context::save(const std::filesystem::path& relative, const std::string& bytes) const {
    if (bytes.size() > remaining()) throw std::runtime_error("Research artifact byte budget exhausted");
    write_text(path(relative), bytes);
}
std::filesystem::path harness::research::resolve_path(const std::string& value, const std::filesystem::path& directory) {
    auto path = std::filesystem::path(widen(value)); return std::filesystem::absolute(path.is_absolute() ? path : directory / path).lexically_normal();
}
std::string harness::research::read_binary(const std::filesystem::path& path, std::size_t limit) {
    if (!std::filesystem::is_regular_file(path) || std::filesystem::file_size(path) > limit) throw std::runtime_error("Input is missing, not a file, or exceeds its byte limit");
    std::ifstream file(path, std::ios::binary); if (!file) throw std::runtime_error("Cannot read research input");
    std::string data(static_cast<std::size_t>(std::filesystem::file_size(path)), '\0'); file.read(data.data(), static_cast<std::streamsize>(data.size()));
    if (file.gcount() != static_cast<std::streamsize>(data.size())) throw std::runtime_error("Research input changed during read");
    return data;
}
std::string harness::research::data_hash(const std::string& data) {
    unsigned char hash[32]{};
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())), static_cast<ULONG>(data.size()), hash, sizeof(hash)) < 0)
        throw std::runtime_error("Cannot hash research input");
    return windows::bytes_hex(hash, sizeof(hash));
}
std::string harness::research::hex_address(std::uint64_t value) { std::ostringstream text; text << "0x" << std::hex << value; return text.str(); }
std::string harness::research::replace_input(std::string argument, const std::string& input) {
    std::size_t position = 0;
    while ((position = argument.find("{input}", position)) != std::string::npos) { argument.replace(position, 7, input); position += input.size(); }
    return argument;
}
static harness::json_t schema(harness::json_t properties, harness::json_t required) {
    return {{"type", "object"}, {"properties", properties}, {"required", required}, {"additionalProperties", false}};
}
harness::json_t harness::research::tool_definitions() {
    const json_t text = {{"type", "string"}}, boolean = {{"type", "boolean"}};
    auto integer = [](std::uint64_t minimum, std::uint64_t maximum) { return json_t{{"type", "integer"}, {"minimum", minimum}, {"maximum", maximum}}; };
    const json_t arguments = {{"type", "array"}, {"items", text}};
    const json_t breakpoint = schema({{"rva", integer(0, 0xffffffff)}, {"module", text}}, {"rva"});
    const json_t memory = schema({{"address", integer(0, 0xffffffffffffffffULL)}, {"length", integer(1, 4096)}}, {"address", "length"});
    json_t launch = {{"executable", text}, {"arguments", arguments}, {"working_directory", text}, {"stdin_file", text},
        {"timeout_ms", integer(1, 3600000)}, {"artifact_limit", integer(1024, 256 * 1024 * 1024)},
        {"entry_breakpoint", boolean}, {"breakpoints", {{"type", "array"}, {"items", breakpoint}}},
        {"step_count", integer(0, 32)}, {"stop_on_breakpoint", boolean}, {"memory_reads", {{"type", "array"}, {"items", memory}}},
        {"max_events", integer(16, 4096)}, {"dump_on_crash", boolean}};
    json_t attach = {{"pid", integer(1, 0xffffffff)}, {"creation_time", text}, {"monitor_ms", integer(1, 3600000)},
        {"memory_reads", {{"type", "array"}, {"items", memory}}}, {"max_events", integer(16, 4096)}, {"dump_on_crash", boolean}};
    return json_t::array({
        {{"name", "debug_run"}, {"description", "Launch a local executable under the Windows user-mode debugger. Capture events, one-shot RVA breakpoints, instruction steps, registers, stacks, memory and unhandled-crash minidumps."}, {"parameters", schema(launch, {"executable", "arguments"})}},
        {{"name", "debug_attach"}, {"description", "Attach to an existing process, collect thread state and debug events for a bounded interval, then detach. Never terminate the attached process."}, {"parameters", schema(attach, {"pid"})}},
        {{"name", "dump_process"}, {"description", "Collect a bounded native minidump of a running process for manual investigation. This does not label a live snapshot as a crash."}, {"parameters", schema({{"pid", integer(1, 0xffffffff)}, {"creation_time", text}, {"artifact_limit", integer(1024, 256 * 1024 * 1024)}}, {"pid"})}},
        {{"name", "crash_info"}, {"description", "Inspect the architecture, exception, threads and modules in a saved Windows minidump."}, {"parameters", schema({{"path", text}}, {"path"})}}
    });
}
bool harness::research::is_research_tool(const std::string& name) {
    return name == "debug_run" || name == "debug_attach" || name == "dump_process" || name == "crash_info";
}
harness::json_t harness::research::worker_execute(const std::string& name, const harness::json_t& args, harness::research::c_context& context) {
    if (name == "debug_run" || name == "debug_attach") { c_debugger debugger(context); return debugger.run(args, "debug", name == "debug_attach"); }
    if (name == "dump_process") return dump_process(args, context);
    if (name == "crash_info") return inspect_dump(resolve_path(args.at("path"), context.directory));
    throw std::runtime_error("Unknown research worker operation");
}
