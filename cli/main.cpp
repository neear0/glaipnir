#include <string>
#include <vector>

#include "c_cli.hpp"

#ifdef _WIN32
#include "glaipnir/core/path_util.hpp"

int wmain(int argc, wchar_t** argv)
{
	std::vector<std::string> args;
	for (int i = 1; i < argc; ++i)
	{
		const auto utf8 = std::filesystem::path{argv[i]}.u8string();
		args.emplace_back(utf8.begin(), utf8.end());
	}
	return glaipnir::cli::c_cli{std::move(args)}.execute();
}
#else
int main(int argc, char** argv)
{
	return glaipnir::cli::c_cli{std::vector<std::string>(argv + 1, argv + argc)}.execute();
}
#endif
