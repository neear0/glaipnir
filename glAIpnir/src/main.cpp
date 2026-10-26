#include "harness/cli/cli.hpp"
#include "harness/core/types.hpp"
#include <iostream>

int wmain(int argc, wchar_t** argv) {
    try {
        std::vector<std::string> arguments;
        for (int index = 1; index < argc; ++index) arguments.push_back(harness::narrow(argv[index]));
        return harness::cli::run(std::move(arguments));
    } catch (const std::exception& error) {
        std::cerr << "glAIpnir: " << error.what() << '\n'; return 1;
    }
}
