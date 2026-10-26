#pragma once
#include "harness/core/types.hpp"

namespace harness::windows {
json_t tool_definitions();
json_t execute_tool(const std::string& name, const json_t& arguments, const std::filesystem::path& default_directory,
    const limits_t& limits, const std::atomic_bool& cancelled);
}
