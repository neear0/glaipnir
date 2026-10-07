#include <chrono>
#include <iostream>
#include <string_view>

#include "support/test_harness.hpp"

int main(int argc, char** argv)
{
	const std::string_view filter = argc > 1 ? argv[1] : "";
	int passed = 0;
	int failed = 0;
	for (const auto& test : glaipnir::test::registry())
	{
		if (!filter.empty() && std::string_view{test.name}.find(filter) == std::string_view::npos)
		{
			continue;
		}
		std::cout << "[ RUN  ] " << test.name << "\n" << std::flush;
		glaipnir::test::current_failure_count() = 0;
		const auto start = std::chrono::steady_clock::now();
		test.body();
		const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
		if (glaipnir::test::current_failure_count() == 0)
		{
			++passed;
			std::cout << "[  OK  ] " << test.name << " (" << ms.count() << " ms)\n";
		}
		else
		{
			++failed;
			std::cout << "[ FAIL ] " << test.name << "\n";
		}
	}
	std::cout << "\n" << passed << " passed, " << failed << " failed\n";
	return failed == 0 ? 0 : 1;
}
