#include "support/test_harness.hpp"

#include <fstream>
#include <iostream>
#include <random>
#include <sstream>

#include "glaipnir/persistence/safe_fs.hpp"

std::vector<glaipnir::test::test_case_t>& glaipnir::test::registry() {
    static std::vector<test_case_t> tests;
    return tests;
}

int& glaipnir::test::current_failure_count() {
    static int failures = 0;
    return failures;
}

void glaipnir::test::report_failure(const char* file, int line, const std::string& expression) {
    ++current_failure_count();
    std::cout << "    FAILED " << std::filesystem::path{file}.filename().string() << ":" << line << ": " << expression << "\n";
}

void glaipnir::test::note(const std::string& message) {
    std::cout << "    note: " << message << "\n";
}

glaipnir::test::c_temp_dir::c_temp_dir() {
    std::random_device device;
    path_ = std::filesystem::temp_directory_path() / ("glaipnir-test-" + std::to_string(device()));
    std::filesystem::create_directories(path_);
    path_ = std::filesystem::canonical(path_);
}

glaipnir::test::c_temp_dir::~c_temp_dir() {
    (void)persistence::remove_tree(path_);
}

std::string glaipnir::test::read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::stringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

void glaipnir::test::write_file(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}
