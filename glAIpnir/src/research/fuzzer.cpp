#include "harness/research/backend.hpp"
#include <algorithm>
#include <fstream>
#include <random>

static std::string mutate(std::string input, std::mt19937& random, std::size_t maximum, const std::vector<std::string>& dictionary) {
    const auto count = 1 + random() % 4;
    for (std::uint32_t step = 0; step < count; ++step) {
        auto operation = random() % 6;
        if (input.empty()) { input += static_cast<char>(random() & 255); continue; }
        auto position = static_cast<std::size_t>(random() % input.size());
        if (operation == 0) input[position] ^= static_cast<char>(1u << (random() % 8));
        else if (operation == 1) input[position] = static_cast<char>(random() & 255);
        else if (operation == 2) {
            auto length = (std::min)(static_cast<std::size_t>(1 + random() % 16), maximum - input.size());
            input.insert(position, length, static_cast<char>(random() & 255));
        } else if (operation == 3) input.erase(position, 1 + random() % 16);
        else if (operation == 4) {
            auto bytes = input.substr(position, 1 + random() % 16); bytes.resize((std::min)(bytes.size(), maximum - input.size())); input.insert(position, bytes);
        } else {
            std::string bytes = dictionary.empty() ? std::string(1, static_cast<char>((random() & 1) ? 0xff : 0)) : dictionary[random() % dictionary.size()];
            bytes.resize((std::min)(bytes.size(), maximum - input.size())); input.insert(position, bytes);
        }
    }
    return input;
}
harness::json_t harness::research::fuzz(const harness::json_t& args, harness::research::c_context& context) {
    const auto executable = resolve_path(args.at("executable"), context.directory);
    const auto executable_hash = sha256(executable); const auto corpus = resolve_path(args.at("corpus"), context.directory);
    if (!std::filesystem::is_directory(corpus)) throw std::runtime_error("Corpus must be a directory of local seed files");
    const auto input_mode = args.value("input_mode", "file");
    const auto arguments = args.at("arguments").get<std::vector<std::string>>();
    if (input_mode == "file" && std::none_of(arguments.begin(), arguments.end(), [](const auto& value) { return value.find("{input}") != std::string::npos; })) throw std::runtime_error("File fuzzing requires {input} in an argument");
    const auto maximum = args.value("max_input_bytes", std::size_t{4096}); const auto iterations = args.value("iterations", 100u);
    const auto random_seed = args.value("random_seed", 0u); const auto max_crashes = args.value("max_crashes", 16u);
    const auto dictionary = args.value("dictionary", std::vector<std::string>{});
    if (dictionary.size() > 64) throw std::runtime_error("Fuzz dictionary is limited to 64 entries");
    for (const auto& entry : dictionary) if (entry.size() > 1024) throw std::runtime_error("Fuzz dictionary entry exceeds 1024 bytes");
    std::vector<std::filesystem::path> paths;
    for (const auto& entry : std::filesystem::directory_iterator(corpus)) {
        if (entry.is_symlink() || !entry.is_regular_file()) continue;
        if (paths.size() == 128) throw std::runtime_error("Corpus is limited to 128 regular files");
        paths.push_back(entry.path());
    }
    std::sort(paths.begin(), paths.end()); std::vector<seed_t> seeds; std::set<std::string> hashes; json_t skipped = json_t::array();
    for (const auto& path : paths) {
        if (std::filesystem::file_size(path) > maximum) { skipped.push_back({{"name", path_text(path.filename())}, {"reason", "seed exceeds max_input_bytes"}}); continue; }
        auto bytes = read_binary(path, maximum); auto hash = data_hash(bytes); if (!hashes.insert(hash).second) continue;
        seeds.push_back({path_text(path.filename()), bytes, hash}); context.save(std::filesystem::path("corpus") / (std::to_string(seeds.size() - 1) + ".bin"), bytes);
    }
    if (seeds.empty()) throw std::runtime_error("Corpus has no usable seeds");
    json_t result = {{"ok", true}, {"outcome", "completed"}, {"random_seed", random_seed}, {"mutation_version", 1}, {"iterations_requested", iterations},
        {"iterations_completed", 0}, {"crash_count", 0}, {"unique_crashes", 0}, {"timeouts", 0}, {"nonzero_exits", 0},
        {"crashes", json_t::array()}, {"seeds", json_t::array()}, {"skipped_seeds", skipped}, {"journal", "campaign.jsonl"}};
    for (const auto& seed : seeds) result["seeds"].push_back({{"name", seed.name}, {"sha256", seed.hash}, {"size", seed.bytes.size()}});
    context.save("campaign.json", dump_json({{"version", HARNESS_VERSION}, {"arguments", args}, {"executable_sha256", executable_hash}, {"seeds", result["seeds"]}}, 2));
    std::mt19937 random(random_seed); std::set<std::string> signatures; std::string journal;
    try {
        for (std::uint32_t iteration = 0; iteration < iterations; ++iteration) {
            if (context.cancelled()) { result["ok"] = false; result["outcome"] = "cancelled"; result["cancelled"] = true; break; }
            auto seed_index = iteration < seeds.size() ? iteration : random() % seeds.size();
            auto input = iteration < seeds.size() ? seeds[seed_index].bytes : mutate(seeds[seed_index].bytes, random, maximum, dictionary);
            const auto relative = std::filesystem::path("cases") / std::to_string(iteration); const auto input_path = relative / "input.bin";
            context.save(input_path, input); const auto input_hash = data_hash(input);
            if (sha256(executable) != executable_hash) throw std::runtime_error("Fuzz target executable changed during campaign");
            json_t entry = {{"iteration", iteration}, {"seed", seed_index}, {"input_sha256", input_hash}, {"input_size", input.size()}, {"input", path_text(input_path)}};
            journal += dump_json({{"state", "started"}, {"case", entry}}) + "\n"; context.save("campaign.jsonl", journal);
            std::vector<std::string> expanded;
            for (const auto& argument : arguments) expanded.push_back(replace_input(argument, path_text(context.path(input_path))));
            json_t debug_args = {{"executable", path_text(executable)}, {"arguments", expanded}, {"entry_breakpoint", false},
                {"timeout_ms", args.value("case_timeout_ms", 1000)}, {"dump_on_crash", signatures.size() < max_crashes}, {"max_events", 64}};
            if (input_mode == "stdin") debug_args["stdin_file"] = path_text(context.path(input_path));
            c_debugger debugger(context); auto execution = debugger.run(debug_args, relative, false, signatures);
            entry["outcome"] = execution.at("outcome"); entry["elapsed_ms"] = execution.at("elapsed_ms");
            if (execution.at("outcome") == "timeout") result["timeouts"] = result.at("timeouts").get<unsigned>() + 1;
            if (execution.at("outcome") == "exit" && execution.value("exit_code", 0u)) result["nonzero_exits"] = result.at("nonzero_exits").get<unsigned>() + 1;
            for (const auto& crash : execution.at("crashes")) {
                result["crash_count"] = result.at("crash_count").get<unsigned>() + 1;
                const auto signature = crash.at("signature").get<std::string>(); const bool unique = signatures.insert(signature).second;
                const auto replay_path = relative / "reproducer.json";
                json_t reproducer = {{"format_version", 1}, {"executable", path_text(executable)}, {"executable_sha256", executable_hash},
                    {"input_file", "input.bin"}, {"input_sha256", input_hash}, {"input_mode", input_mode}, {"arguments_template", arguments},
                    {"working_directory", path_text(context.directory)}, {"expected_signature", signature}, {"timeout_ms", args.value("case_timeout_ms", 1000)}};
                context.save(replay_path, dump_json(reproducer, 2));
                json_t summary = {{"signature", signature}, {"unique", unique}, {"iteration", iteration}, {"exception_code", crash.at("exception_code")},
                    {"manifest", crash.at("manifest")}, {"reproducer", path_text(replay_path)}, {"input", path_text(input_path)}, {"verified_vulnerability", false}};
                if (crash.contains("minidump")) { summary["minidump"] = crash.at("minidump"); summary["dump_result"] = crash.at("dump_result"); }
                result["crashes"].push_back(summary);
            }
            result["iterations_completed"] = iteration + 1; result["unique_crashes"] = signatures.size();
            journal += dump_json({{"state", "completed"}, {"case", entry}}) + "\n"; context.save("campaign.jsonl", journal);
            context.save("summary.json", dump_json(result, 2));
            if (args.value("stop_on_crash", false) && !execution.at("crashes").empty()) { result["outcome"] = "stopped_on_crash"; break; }
            if (signatures.size() >= max_crashes) { result["outcome"] = "crash_limit"; break; }
            if (execution.at("outcome") == "cancelled") { result["ok"] = false; result["outcome"] = "cancelled"; result["cancelled"] = true; break; }
        }
    } catch (const std::exception& error) { result["ok"] = false; result["outcome"] = "error"; result["error"] = error.what(); }
    if (dump_json(result).size() > context.limits.output_limit) {
        context.save("summary.json", dump_json(result, 2)); result["crashes_truncated"] = true;
        while (result["crashes"].size() > 1 && dump_json(result).size() > context.limits.output_limit) result["crashes"].erase(result["crashes"].end() - 1);
    }
    return result;
}
harness::json_t harness::research::replay(const harness::json_t& args, harness::research::c_context& context) {
    const auto path = resolve_path(args.at("manifest"), context.directory); const auto manifest = json_t::parse(read_binary(path, 1024 * 1024));
    if (manifest.at("format_version") != 1) throw std::runtime_error("Unsupported reproducer format");
    auto executable = resolve_path(args.value("executable", manifest.at("executable").get<std::string>()), context.directory);
    if (sha256(executable) != manifest.at("executable_sha256").get<std::string>()) throw std::runtime_error("Reproducer executable SHA-256 does not match");
    const auto mode = manifest.at("input_mode").get<std::string>();
    if (mode != "none" && mode != "file" && mode != "stdin") throw std::runtime_error("Invalid reproducer input mode");
    std::filesystem::path input_path;
    if (mode != "none") {
        auto input_relative = std::filesystem::path(widen(manifest.at("input_file")));
        if (input_relative.is_absolute() || input_relative.has_root_name()) throw std::runtime_error("Reproducer input must be relative to its manifest");
        for (const auto& part : input_relative) if (part == L"..") throw std::runtime_error("Reproducer input escapes its manifest directory");
        auto input = read_binary(path.parent_path() / input_relative, 1024 * 1024);
        if (data_hash(input) != manifest.at("input_sha256").get<std::string>()) throw std::runtime_error("Reproducer input SHA-256 does not match");
        context.save("replay/input.bin", input); input_path = context.path("replay/input.bin");
    }
    auto arguments = manifest.at("arguments_template").get<std::vector<std::string>>();
    for (auto& argument : arguments) { if (argument.find('\0') != std::string::npos) throw std::runtime_error("NUL in reproducer argument"); if (mode != "none") argument = replace_input(argument, path_text(input_path)); }
    context.directory = resolve_path(args.value("working_directory", manifest.at("working_directory").get<std::string>()), context.directory);
    json_t debug_args = {{"executable", path_text(executable)}, {"arguments", arguments}, {"entry_breakpoint", false}, {"timeout_ms", args.value("timeout_ms", manifest.value("timeout_ms", 1000))}};
    if (mode == "stdin") debug_args["stdin_file"] = path_text(input_path);
    c_debugger debugger(context); auto result = debugger.run(debug_args, "replay");
    result["expected_signature"] = manifest.at("expected_signature");
    result["reproduced"] = !result.at("crashes").empty() && result.at("crashes").front().at("signature") == manifest.at("expected_signature");
    result["ok"] = result.at("reproduced"); return result;
}
