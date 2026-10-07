#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace glaipnir::test {

struct test_case_t {
    const char* name;
    void (*body)();
};

std::vector<test_case_t>& registry();

struct registrar_t {
    registrar_t(const char* name, void (*body)()) { registry().push_back({name, body}); }
};

int& current_failure_count();

void report_failure(const char* file, int line, const std::string& expression);

void note(const std::string& message);

class c_temp_dir {
public:
    c_temp_dir();
    ~c_temp_dir();
    c_temp_dir(const c_temp_dir&) = delete;
    c_temp_dir& operator=(const c_temp_dir&) = delete;

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

std::string read_file(const std::filesystem::path& path);

void write_file(const std::filesystem::path& path, const std::string& content);

}

#define glaipnir_test(name)                                                                                            \
    static void name();                                                                                                \
    static ::glaipnir::test::registrar_t name##_registrar{#name, &name};                                               \
    static void name()

#define glaipnir_check(expr)                                                                                           \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            ::glaipnir::test::report_failure(__FILE__, __LINE__, #expr);                                               \
        }                                                                                                              \
    } while (false)

#define glaipnir_require(expr)                                                                                         \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            ::glaipnir::test::report_failure(__FILE__, __LINE__, #expr);                                               \
            return;                                                                                                    \
        }                                                                                                              \
    } while (false)

#define glaipnir_require_ok(result)                                                                                    \
    do {                                                                                                               \
        if (!(result)) {                                                                                               \
            ::glaipnir::test::report_failure(__FILE__, __LINE__,                                                       \
                                             std::string{#result " failed: "} + ::glaipnir::core::describe((result).error())); \
            return;                                                                                                    \
        }                                                                                                              \
    } while (false)
