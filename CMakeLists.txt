cmake_minimum_required(VERSION 3.24)
project(glaipnir VERSION 0.4.0 LANGUAGES C CXX)
set(CMAKE_VS_GLOBALS "VcpkgEnabled=false")

if(NOT WIN32)
    message(FATAL_ERROR "glAIpnir requires Windows.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "glAIpnir requires a 64-bit build.")
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
    glAIpnir/src/storage/research_store.cpp
    glAIpnir/src/windows/tools.cpp
    glAIpnir/src/windows/analysis.cpp
    glAIpnir/src/windows/process.cpp
    glAIpnir/src/windows/service.cpp
    glAIpnir/src/windows/registry.cpp
    glAIpnir/src/windows/token.cpp
    glAIpnir/src/windows/security.cpp
    glAIpnir/src/research/backend.cpp
    glAIpnir/src/research/transport.cpp
    glAIpnir/src/research/debugger.cpp
    glAIpnir/src/research/crash.cpp
    glAIpnir/src/research/fuzzer.cpp
    glAIpnir/src/research/session.cpp
    glAIpnir/src/ai/model.cpp
    glAIpnir/src/ai/context.cpp
    glAIpnir/src/ai/orchestrator.cpp
    glAIpnir/src/ai/http.cpp
    glAIpnir/src/cli/cli.cpp)
target_include_directories(harness PUBLIC glAIpnir/include)
target_link_libraries(harness PUBLIC nlohmann_json::nlohmann_json PRIVATE sqlite3 winhttp bcrypt advapi32 psapi dbghelp)
target_compile_features(harness PUBLIC cxx_std_20)
target_compile_definitions(harness PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX HARNESS_VERSION="${PROJECT_VERSION}")
set_target_properties(harness PROPERTIES CXX_EXTENSIONS NO)
add_executable(glaipnir glAIpnir/src/main.cpp)
add_executable(glaipnir_worker glAIpnir/src/research/worker_main.cpp)
include(ExternalProject)
set(wow64_binary_dir "${CMAKE_BINARY_DIR}/wow64")
ExternalProject_Add(wow64_tools
    BUILD_ALWAYS TRUE
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/cmake/wow64
    BINARY_DIR ${wow64_binary_dir}
    CMAKE_GENERATOR "Visual Studio 17 2022"
    CMAKE_GENERATOR_PLATFORM Win32
    CMAKE_ARGS -DHARNESS_VERSION=${PROJECT_VERSION}
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> -- /m:1 /v:minimal
    INSTALL_COMMAND "")
add_custom_target(stage_wow64_helper
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${wow64_binary_dir}/$<CONFIG>/glAIpnir-dump32.exe ${CMAKE_BINARY_DIR}/$<CONFIG>/glAIpnir-dump32.exe
    DEPENDS wow64_tools)
add_dependencies(glaipnir_worker stage_wow64_helper)
target_link_libraries(glaipnir_worker PRIVATE harness)
set_target_properties(glaipnir_worker PROPERTIES OUTPUT_NAME glAIpnir-worker)
add_dependencies(glaipnir glaipnir_worker)
target_link_libraries(glaipnir PRIVATE harness)
set_target_properties(glaipnir PROPERTIES OUTPUT_NAME glAIpnir)
install(TARGETS glaipnir glaipnir_worker RUNTIME DESTINATION bin)
install(PROGRAMS ${wow64_binary_dir}/$<CONFIG>/glAIpnir-dump32.exe DESTINATION bin)
install(FILES README.md THIRD_PARTY_NOTICES.md DESTINATION .)
install(FILES examples/config.json DESTINATION examples)
install(FILES glAIpnir/coms.md DESTINATION glAIpnir)
install(DIRECTORY docs DESTINATION .)
function(harness_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /sdl /EHsc /utf-8)
    endif()
endfunction()
harness_warnings(harness)
harness_warnings(glaipnir)
harness_warnings(glaipnir_worker)
include(CTest)
if(BUILD_TESTING)
    add_executable(harness_fixture tests/fixture.cpp)
    add_executable(research_fixture tests/research_fixture.cpp)
    target_compile_features(research_fixture PRIVATE cxx_std_20)
    target_compile_options(research_fixture PRIVATE /utf-8)
    target_compile_features(harness_fixture PRIVATE cxx_std_20)
    add_executable(harness_tests tests/tests.cpp)
    target_link_libraries(harness_tests PRIVATE harness ws2_32)
    add_dependencies(harness_tests glaipnir_worker)
    harness_warnings(harness_tests)
    add_test(NAME harness_tests COMMAND harness_tests $<TARGET_FILE:harness_fixture>)
    set_tests_properties(harness_tests PROPERTIES TIMEOUT 90)
    add_executable(windows_tests tests/windows_tests.cpp)
    target_link_libraries(windows_tests PRIVATE harness sqlite3 advapi32)
    harness_warnings(windows_tests)
    add_test(NAME windows_analysis COMMAND windows_tests $<TARGET_FILE:harness_fixture>)
    set_tests_properties(windows_analysis PROPERTIES TIMEOUT 45)
    add_executable(research_tests tests/research_tests.cpp)
    target_link_libraries(research_tests PRIVATE harness advapi32)
    add_dependencies(research_tests glaipnir_worker research_fixture)
    harness_warnings(research_tests)
    add_test(NAME research_backend COMMAND research_tests $<TARGET_FILE:research_fixture>)
    set_tests_properties(research_backend PROPERTIES TIMEOUT 120)
    add_executable(research_loop_tests tests/research_loop_tests.cpp)
    target_link_libraries(research_loop_tests PRIVATE harness sqlite3)
    add_dependencies(research_loop_tests glaipnir_worker research_fixture)
    harness_warnings(research_loop_tests)
    add_test(NAME research_loop COMMAND research_loop_tests $<TARGET_FILE:research_fixture>)
    set_tests_properties(research_loop PROPERTIES TIMEOUT 120)
    set(HARNESS_X86_FIXTURE_ROOT "${CMAKE_SOURCE_DIR}/out/build/research-x86" CACHE PATH "Optional standalone Win32 research fixture build")
    if(EXISTS "${HARNESS_X86_FIXTURE_ROOT}/CMakeCache.txt")
        add_custom_target(research_fixture_x86
            COMMAND ${CMAKE_COMMAND} --build ${HARNESS_X86_FIXTURE_ROOT} --config $<CONFIG>
            COMMENT "Building WOW64 research fixture")
        add_dependencies(research_tests research_fixture_x86)
        add_test(NAME research_backend_x86 COMMAND research_tests ${HARNESS_X86_FIXTURE_ROOT}/$<CONFIG>/research_fixture.exe x86)
        set_tests_properties(research_backend_x86 PROPERTIES TIMEOUT 120)
    endif()
    add_test(NAME cli_help COMMAND glaipnir --help)
    add_test(NAME cli_workflow COMMAND powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
        -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.ps1
        -Harness $<TARGET_FILE:glaipnir> -Fixture $<TARGET_FILE:harness_fixture>
        -ExpectedVersion ${PROJECT_VERSION}
        -Root ${CMAKE_CURRENT_BINARY_DIR}/cli-test-data/$<CONFIG>)
    set_tests_properties(cli_workflow PROPERTIES TIMEOUT 60)
    add_test(NAME research_cli COMMAND powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
        -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/research_cli.ps1
        -Harness $<TARGET_FILE:glaipnir> -Fixture $<TARGET_FILE:research_fixture>
        -Root ${CMAKE_CURRENT_BINARY_DIR}/research-cli-data/$<CONFIG>)
    set_tests_properties(research_cli PROPERTIES TIMEOUT 60)
    add_test(NAME research_loop_cli COMMAND powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
        -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/research_loop_cli.ps1
        -Harness $<TARGET_FILE:glaipnir> -Fixture $<TARGET_FILE:research_fixture>
        -Root ${CMAKE_CURRENT_BINARY_DIR}/research-loop-cli-data/$<CONFIG>)
    set_tests_properties(research_loop_cli PROPERTIES TIMEOUT 60)
endif()
set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT glaipnir)
