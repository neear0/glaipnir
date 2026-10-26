#include "harness/cli/cli.hpp"
#include "harness/core/runtime.hpp"
#include "harness/windows/tools.hpp"
#include <iostream>
#include <sstream>
#include <cctype>

static std::atomic_bool cancelled{false};
static BOOL WINAPI handle_control(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) { cancelled.store(true); return TRUE; }
    return FALSE;
}
static void help() {
    std::cout << "glAIpnir 0.1.0 - Windows research harness\n"
        "Global options: --store PATH --config FILE --json\n"
        "  session create TARGET\n  session list\n  session show ID\n  session export ID DIRECTORY\n"
        "  tools list\n  tool run ID TOOL JSON|@FILE\n  investigate ID PROFILE GOAL\n  shell\n"
        "Interactive commands use the same syntax. Quote arguments with double quotes.\n"
        "Use @FILE for JSON containing quotes. Type exit to leave the shell.\n";
}
static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> result; std::string token; bool quoted = false, active = false;
    for (std::size_t index = 0; index < line.size(); ++index) {
        const auto character = line[index];
        if (character == '\\' && index + 1 < line.size() && line[index + 1] == '"') { token += '"'; ++index; active = true; }
        else if (character == '"') { quoted = !quoted; active = true; }
        else if (std::isspace(static_cast<unsigned char>(character)) && !quoted) {
            if (active) { result.push_back(token); token.clear(); active = false; }
        } else { token += character; active = true; }
    }
    if (quoted) throw std::runtime_error("Unclosed quote");
    if (active) result.push_back(token); return result;
}
static harness::json_t command(const std::vector<std::string>& args, harness::c_runtime& runtime, harness::storage::c_evidence_store& store) {
    if (args.size() == 2 && args[0] == "tools" && args[1] == "list") return harness::windows::tool_definitions();
    if (args.size() == 2 && args[0] == "session" && args[1] == "list") return store.list_sessions();
    if (args.size() == 3 && args[0] == "session" && args[1] == "create") {
        auto id = runtime.create_session(harness::widen(args[2])); return {{"session_id", id}};
    }
    if (args.size() == 3 && args[0] == "session" && args[1] == "show") return {{"session", store.session(args[2])}, {"records", store.records(args[2])}};
    if (args.size() == 4 && args[0] == "session" && args[1] == "export") return store.export_session(args[2], harness::widen(args[3]));
    if (args.size() == 5 && args[0] == "tool" && args[1] == "run") {
        auto input = args[4].starts_with('@') ? harness::read_json(harness::widen(args[4].substr(1))) : harness::json_t::parse(args[4]);
        return runtime.dispatch(args[2], args[3], input);
    }
    if (args.size() >= 4 && args[0] == "investigate") {
        std::string goal = args[3]; for (std::size_t index = 4; index < args.size(); ++index) goal += " " + args[index];
        return runtime.investigate(args[1], goal, args[2]);
    }
    throw std::runtime_error("Unknown command or invalid arguments; use --help");
}
int harness::cli::run(std::vector<std::string> arguments) {
    SetConsoleCP(CP_UTF8); SetConsoleOutputCP(CP_UTF8);
    if (arguments.empty() || arguments[0] == "--help" || arguments[0] == "help") { help(); return 0; }
    if (arguments[0] == "--version") { std::cout << "0.1.0\n"; return 0; }
    std::filesystem::path root = L".glaipnir", config_path;
    bool json_output = false;
    std::vector<std::string> args;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        if (arguments[index] == "--json") json_output = true;
        else if (arguments[index] == "--store" || arguments[index] == "--config") {
            const auto option = arguments[index];
            if (++index == arguments.size()) throw std::runtime_error("Missing value for " + option);
            (option == "--store" ? root : config_path) = widen(arguments[index]);
        } else args.push_back(arguments[index]);
    }
    json_t config = config_path.empty() ? json_t::object() : read_json(config_path);
    config = public_config(config);
    storage::c_evidence_store store(root); c_runtime runtime(store, config, cancelled);
    check_win(SetConsoleCtrlHandler(handle_control, TRUE) != FALSE, "Install cancellation handler");
    auto print = [json_output](const json_t& result) { std::cout << dump_json(result, json_output ? -1 : 2) << '\n'; };
    int result_code = 0;
    try {
        if (args.size() == 1 && args[0] == "shell") {
            const bool interactive = GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR;
            if (interactive) std::cerr << "glAIpnir 0.1.0. Use help or exit.\n";
            std::string line;
            while (true) {
                if (interactive) std::cerr << "glaipnir> ";
                if (!std::getline(std::cin, line)) break;
                if (line.starts_with("\xef\xbb\xbf")) line.erase(0, 3);
                cancelled.store(false);
                try {
                    auto tokens = tokenize(line);
                    if (tokens.empty()) continue;
                    if (tokens[0] == "exit") break;
                    if (tokens[0] == "help" || tokens[0] == "--help") { help(); continue; }
                    print(command(tokens, runtime, store));
                } catch (const std::exception& error) { std::cerr << "glAIpnir: " << error.what() << '\n'; }
            }
        } else {
            auto result = command(args, runtime, store); print(result);
            if (result.is_object() && !result.value("ok", true)) result_code = cancelled.load() ? 130 : 1;
        }
    } catch (...) { SetConsoleCtrlHandler(handle_control, FALSE); throw; }
    SetConsoleCtrlHandler(handle_control, FALSE); return result_code;
}
