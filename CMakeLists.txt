cmake_minimum_required(VERSION 3.24)
project(glaipnir VERSION 0.1.0 LANGUAGES C CXX)
set(CMAKE_VS_GLOBALS "VcpkgEnabled=false")

if(NOT WIN32)
    message(FATAL_ERROR "glAIpnir requires Windows.")
endif()

include(FetchContent)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa)
FetchContent_MakeAvailable(json)
FetchContent_Declare(sqlite
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
    URL_HASH SHA256=0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9)
FetchContent_MakeAvailable(sqlite)
add_library(sqlite3 STATIC ${sqlite_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${sqlite_SOURCE_DIR})
target_compile_definitions(sqlite3 PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION)

add_library(harness STATIC
    glAIpnir/src/core/runtime.cpp
    glAIpnir/src/core/util.cpp
    glAIpnir/src/storage/store.cpp
    glAIpnir/src/windows/tools.cpp
    glAIpnir/src/ai/model.cpp
    glAIpnir/src/ai/http.cpp
    glAIpnir/src/cli/cli.cpp)
target_include_directories(harness PUBLIC glAIpnir/include)
target_link_libraries(harness PUBLIC nlohmann_json::nlohmann_json PRIVATE sqlite3 winhttp bcrypt)
target_compile_features(harness PUBLIC cxx_std_20)
target_compile_definitions(harness PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(harness PROPERTIES CXX_EXTENSIONS NO)
add_executable(glaipnir glAIpnir/src/main.cpp)
target_link_libraries(glaipnir PRIVATE harness)
set_target_properties(glaipnir PROPERTIES OUTPUT_NAME glAIpnir)
install(TARGETS glaipnir RUNTIME DESTINATION bin)
install(FILES README.md THIRD_PARTY_NOTICES.md DESTINATION .)
install(FILES examples/config.json DESTINATION examples)
function(harness_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /sdl /EHsc /utf-8)
    endif()
endfunction()
harness_warnings(harness)
harness_warnings(glaipnir)
include(CTest)
if(BUILD_TESTING)
    add_executable(harness_fixture tests/fixture.cpp)
    target_compile_features(harness_fixture PRIVATE cxx_std_20)
    add_executable(harness_tests tests/tests.cpp)
    target_link_libraries(harness_tests PRIVATE harness ws2_32)
    harness_warnings(harness_tests)
    add_test(NAME harness_tests COMMAND harness_tests $<TARGET_FILE:harness_fixture>)
    set_tests_properties(harness_tests PROPERTIES TIMEOUT 90)
    add_test(NAME cli_help COMMAND glaipnir --help)
    add_test(NAME cli_workflow COMMAND powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
        -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.ps1
        -Harness $<TARGET_FILE:glaipnir> -Fixture $<TARGET_FILE:harness_fixture>
        -Root ${CMAKE_CURRENT_BINARY_DIR}/cli-test-data/$<CONFIG>)
    set_tests_properties(cli_workflow PROPERTIES TIMEOUT 30)
endif()
set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT glaipnir)
