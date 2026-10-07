#pragma once

#include <filesystem>
#include <string>

namespace glaipnir::test {

std::filesystem::path source_root();

bool is_snake_case(const std::string& name);

std::string strip_comments_and_strings(const std::string& code);

}
