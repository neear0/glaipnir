#include "test_harness.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string_view>

#include "glaipnir/persistence/safe_fs.hpp"

namespace glaipnir::test {

namespace {

int failures_in_current = 0;

} // namespace

std::vector<test_case_t>& registry() {
    static std::vector<test_case_t> tests;
    return tests;
}

void report_failure(const char* file, int line, const std::string& expression) {
    ++failures_in_current;
    std::cout << "    FAILED " << std::filesystem::path{file}.filename().string() << ":" << line << ": " << expression << "\n";
}

void note(const std::string& message) {
    std::cout << "    note: " << message << "\n";
}

c_temp_dir::c_temp_dir() {
    std::random_device device;
    path_ = std::filesystem::temp_directory_path() / ("glaipnir-test-" + std::to_string(device()));
    std::filesystem::create_directories(path_);
    path_ = std::filesystem::canonical(path_);
}

c_temp_dir::~c_temp_dir() {
    (void)persistence::remove_tree(path_);
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::stringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

void write_file(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}

} // namespace glaipnir::test

int main(int argc, char** argv) {
    using namespace glaipnir::test;
    const std::string_view filter = argc > 1 ? argv[1] : "";
    int passed = 0;
    int failed = 0;
    for (const auto& test : registry()) {
        if (!filter.empty() && std::string_view{test.name}.find(filter) == std::string_view::npos) {
            continue;
        }
        std::cout << "[ RUN  ] " << test.name << "\n" << std::flush;
        failures_in_current = 0;
        const auto start = std::chrono::steady_clock::now();
        test.body();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        if (failures_in_current == 0) {
            ++passed;
            std::cout << "[  OK  ] " << test.name << " (" << ms.count() << " ms)\n";
        } else {
            ++failed;
            std::cout << "[ FAIL ] " << test.name << "\n";
        }
    }
    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
