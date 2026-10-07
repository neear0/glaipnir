#include "detail/cli_output.hpp"

#include <format>
#include <iostream>
#include <random>

#include "c_cli.hpp"

void glaipnir::cli::detail::print_error(const core::error_t& error) {
    std::cerr << "glaipnir: " << core::describe(error) << "\n";
}

int glaipnir::cli::detail::fail(const core::error_t& error) {
    print_error(error);
    return exit_internal;
}

int glaipnir::cli::detail::usage_error(std::string_view message) {
    std::cerr << "glaipnir: " << message << "\n(run `glaipnir help` for usage)\n";
    return exit_usage;
}

std::string glaipnir::cli::detail::random_suffix() {
    std::random_device device;
    return std::format("{:08x}", device());
}
