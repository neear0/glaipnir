#pragma once

// Minimal self-registering test harness. No third-party framework so the test binary builds
// with nothing but the compiler, like the rest of glaipnir.

#include <filesystem>
#include <string>
#include <vector>

namespace glaipnir::test {

/// One registered test.
struct test_case_t {
    const char* name;
    void (*body)();
};

/// All tests, in registration order.
std::vector<test_case_t>& registry();

/// Registers a test at static-initialization time.
struct registrar_t {
    registrar_t(const char* name, void (*body)()) { registry().push_back({name, body}); }
};

/// Records a failed check for the running test.
void report_failure(const char* file, int line, const std::string& expression);

/// Prints a note under the running test (for skipped or informational checks).
void note(const std::string& message);

/// Fresh, empty directory under the system temp dir, removed on destruction.
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

/// Whole-file read; empty string if missing.
std::string read_file(const std::filesystem::path& path);

/// Whole-file write.
void write_file(const std::filesystem::path& path, const std::string& content);

} // namespace glaipnir::test

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

/// Like glaipnir_require for result_t values, printing the error on failure.
#define glaipnir_require_ok(result)                                                                                    \
    do {                                                                                                               \
        if (!(result)) {                                                                                               \
            ::glaipnir::test::report_failure(__FILE__, __LINE__,                                                       \
                                             std::string{#result " failed: "} + ::glaipnir::core::describe((result).error())); \
            return;                                                                                                    \
        }                                                                                                              \
    } while (false)
