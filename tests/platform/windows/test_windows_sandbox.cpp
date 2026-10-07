#ifdef _WIN32

#include "support/test_harness.hpp"

#include <thread>

#include "platform/windows/detail/win_util.hpp"

#include <shellapi.h>

#include "glaipnir/core/c_sandbox.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/platform/windows/command_line.hpp"
#include "support/sandbox_fixture.hpp"

using glaipnir::core::c_sandbox;
using glaipnir::isolation::termination_reason;
using glaipnir::test::cmd_exe;
using glaipnir::test::path_text;
using glaipnir::test::read_file;
using glaipnir::test::sandbox_fixture_t;
using glaipnir::test::write_file;

glaipnir_test(win_quote_argument_round_trips_through_commandlinetoargvw)
{
	const std::vector<std::wstring> tricky{
		L"plain", L"with space", L"", L"\"quoted\"", L"trailing\\", L"trailing space\\", L"a\\\\\"b",
		L"\\\\server\\share\\",
		L"tab\there", L"semi;colon&amp|pipe", L"%PATH%", L"unicode-\x00e9\x4e2d",
	};
	std::vector<std::wstring> argv{L"C:\\prog.exe"};
	argv.insert(argv.end(), tricky.begin(), tricky.end());
	auto line = glaipnir::platform::windows::build_command_line(argv);
	glaipnir_require_ok(line);
	int count = 0;
	wchar_t** parsed = CommandLineToArgvW(line->c_str(), &count);
	glaipnir_require(parsed != nullptr);
	glaipnir_check(count == static_cast<int>(argv.size()));
	for (int i = 0; i < count && i < static_cast<int>(argv.size()); ++i)
	{
		glaipnir_check(argv[static_cast<std::size_t>(i)] == parsed[i]);
	}
	LocalFree(parsed);
	glaipnir_check(!glaipnir::platform::windows::build_command_line({L"bad\"name.exe"}).has_value());
}

glaipnir_test(win_resolve_executable_uses_given_path_only)
{
	auto found = glaipnir::platform::windows::resolve_executable(L"cmd", L"C:\\Windows\\System32", L".COM;.EXE");
	glaipnir_require_ok(found);
	glaipnir_check(glaipnir::core::is_same_or_inside(*found, "C:\\Windows\\System32\\cmd.exe"));
	glaipnir_check(!glaipnir::platform::windows::resolve_executable(L"cmd", L"C:\\nonexistent", L".EXE").has_value());
}

glaipnir_test(win_sandbox_runs_in_workspace)
{
	sandbox_fixture_t fixture;
	auto result = fixture.run("basic", "", "echo hello> out.txt");
	glaipnir_require_ok(result);
	glaipnir_check(result->exit_code == 0);
	glaipnir_check(result->reason == termination_reason::exited);
	glaipnir_check(read_file(fixture.workspace("basic") / "out.txt") == "hello\r\n");
}

glaipnir_test(win_sandbox_cannot_read_ungranted_files_until_granted)
{
	sandbox_fixture_t fixture;
	const auto host_dir = fixture.temp.path() / "host-data";
	std::filesystem::create_directories(host_dir);
	write_file(host_dir / "secret.txt", "TOP-SECRET");

	auto denied = fixture.run("reader", "", "type " + path_text(host_dir / "secret.txt") + " > out.txt 2>&1");
	glaipnir_require_ok(denied);
	glaipnir_check(denied->exit_code != 0);
	glaipnir_check(read_file(fixture.workspace("reader") / "out.txt").find("TOP-SECRET") == std::string::npos);

	const std::string grant = "[filesystem]\nread = ['" + path_text(host_dir) + "']\n";
	auto allowed = fixture.run("reader", grant, "type " + path_text(host_dir / "secret.txt") + " > out.txt 2>&1");
	glaipnir_require_ok(allowed);
	glaipnir_check(allowed->exit_code == 0);
	glaipnir_check(read_file(fixture.workspace("reader") / "out.txt") == "TOP-SECRET");

	auto write_attempt = fixture.run("reader", grant, "echo pwned> " + path_text(host_dir / "new.txt"));
	glaipnir_require_ok(write_attempt);
	glaipnir_check(!std::filesystem::exists(host_dir / "new.txt"));

	auto revoked = fixture.run("reader", "", "type " + path_text(host_dir / "secret.txt") + " > out.txt 2>&1");
	glaipnir_require_ok(revoked);
	glaipnir_check(read_file(fixture.workspace("reader") / "out.txt").find("TOP-SECRET") == std::string::npos);
}

glaipnir_test(win_sandbox_write_grant_downgrade_takes_effect)
{
	sandbox_fixture_t fixture;
	const auto shared = fixture.temp.path() / "shared";
	std::filesystem::create_directories(shared);
	const auto target = path_text(shared / "file.txt");

	auto written = fixture.run("writer", "[filesystem]\nwrite = ['" + path_text(shared) + "']\n",
	                           "echo one> " + target);
	glaipnir_require_ok(written);
	glaipnir_check(read_file(shared / "file.txt") == "one\r\n");

	auto downgraded = fixture.run("writer", "[filesystem]\nread = ['" + path_text(shared) + "']\n",
	                              "echo two> " + target);
	glaipnir_require_ok(downgraded);
	glaipnir_check(read_file(shared / "file.txt") == "one\r\n");
}

glaipnir_test(win_sandbox_cannot_write_outside_workspace)
{
	sandbox_fixture_t fixture;
	const auto outside = fixture.temp.path() / "outside.txt";
	auto result = fixture.run("escape", "", "echo pwned> " + path_text(outside));
	glaipnir_require_ok(result);
	glaipnir_check(!std::filesystem::exists(outside));
	auto profile = fixture.run("escape", "", "echo pwned> " + path_text(fixture.host.home / "glaipnir-escape.txt"));
	glaipnir_require_ok(profile);
	glaipnir_check(!std::filesystem::exists(fixture.host.home / "glaipnir-escape.txt"));
}

glaipnir_test(win_sessions_cannot_see_each_other)
{
	sandbox_fixture_t fixture;
	auto first = fixture.run("tenant-a", "", "echo a-private> private.txt");
	glaipnir_require_ok(first);
	glaipnir_require(std::filesystem::exists(fixture.workspace("tenant-a") / "private.txt"));
	auto second = fixture.run("tenant-b", "",
	                          "type " + path_text(fixture.workspace("tenant-a") / "private.txt") + " > out.txt 2>&1");
	glaipnir_require_ok(second);
	glaipnir_check(read_file(fixture.workspace("tenant-b") / "out.txt").find("a-private") == std::string::npos);
}

glaipnir_test(win_environment_is_not_inherited)
{
	sandbox_fixture_t fixture;
	SetEnvironmentVariableW(L"GLAIPNIR_TEST_HOST_ONLY", L"leaked-value");
	SetEnvironmentVariableW(L"HOST_VISIBLE", L"passed-value");
	auto result = fixture.run("env", "[env]\npass = [\"HOST_VISIBLE\"]\n[env.set]\nFROM_POLICY = \"set-value\"\n",
	                          "set > env.txt");
	SetEnvironmentVariableW(L"GLAIPNIR_TEST_HOST_ONLY", nullptr);
	SetEnvironmentVariableW(L"HOST_VISIBLE", nullptr);
	glaipnir_require_ok(result);
	const auto env = read_file(fixture.workspace("env") / "env.txt");
	glaipnir_check(env.find("leaked-value") == std::string::npos);
	glaipnir_check(env.find("HOST_VISIBLE=passed-value") != std::string::npos);
	glaipnir_check(env.find("FROM_POLICY=set-value") != std::string::npos);
	glaipnir_check(env.find("GLAIPNIR_SESSION=env") != std::string::npos);
	glaipnir_check(env.find("USERPROFILE=" + path_text(fixture.host.home) + "\r") == std::string::npos);
}

glaipnir_test(win_child_processes_need_capability)
{
	sandbox_fixture_t fixture;
	const std::string nested = "cmd /d /c echo nested> nested.txt";
	const auto output = fixture.workspace("children") / "nested.txt";
	auto blocked = fixture.run("children", "[env]\npass = [\"PATH\"]\n", nested);
	glaipnir_require_ok(blocked);
	glaipnir_check(read_file(output).find("nested") == std::string::npos);

	auto allowed = fixture.run("children", "[env]\npass = [\"PATH\"]\n[capabilities]\nchild_processes = true\n",
	                           nested);
	glaipnir_require_ok(allowed);
	glaipnir_check(read_file(output).find("nested") != std::string::npos);
}

glaipnir_test(win_wall_timeout_kills_the_tree)
{
	sandbox_fixture_t fixture;
	auto result = fixture.run("slow", "[limits]\nwall_timeout_s = 1\n", "for /L %i in (1,1,2000000000) do @rem");
	glaipnir_require_ok(result);
	glaipnir_check(result->reason == termination_reason::wall_timeout);
	glaipnir_check(result->wall_time < std::chrono::seconds{10});
}

glaipnir_test(win_cpu_timeout_kills_the_tree)
{
	sandbox_fixture_t fixture;
	auto result = fixture.run("spin", "[limits]\ncpu_timeout_s = 1\nwall_timeout_s = 60\n",
	                          "for /L %i in (1,1,2000000000) do @rem");
	glaipnir_require_ok(result);
	glaipnir_check(result->reason == termination_reason::cpu_timeout);
	glaipnir_check(result->wall_time < std::chrono::seconds{30});
}

glaipnir_test(win_pause_freezes_and_resume_continues)
{
	sandbox_fixture_t fixture;
	auto policy = fixture.policy_from("[limits]\nwall_timeout_s = 60\n");
	glaipnir_require_ok(policy);
	auto session = fixture.session("pausable");
	glaipnir_require_ok(session);
	auto sandbox = c_sandbox::create(std::move(*policy), *session);
	glaipnir_require_ok(sandbox);
	glaipnir_require(
		sandbox->start({std::string{cmd_exe}, "/d", "/c", "for /L %i in (1,1,2000000) do @echo %i>> count.txt"})
		.has_value());

	const auto counter = fixture.workspace("pausable") / "count.txt";
	const auto size = [&]
	{
		std::error_code ec;
		const auto value = std::filesystem::file_size(counter, ec);
		return ec ? 0 : value;
	};
	std::this_thread::sleep_for(std::chrono::milliseconds{500});
	glaipnir_require(sandbox->pause().has_value());
	std::this_thread::sleep_for(std::chrono::milliseconds{200});
	const auto frozen = size();
	std::this_thread::sleep_for(std::chrono::milliseconds{500});
	glaipnir_check(frozen > 0);
	glaipnir_check(size() == frozen);

	glaipnir_require(sandbox->resume().has_value());
	std::this_thread::sleep_for(std::chrono::milliseconds{500});
	glaipnir_check(size() > frozen);

	glaipnir_require(sandbox->terminate().has_value());
	auto result = sandbox->wait();
	glaipnir_require_ok(result);
	glaipnir_check(result->reason == termination_reason::terminated);
}

glaipnir_test(win_rollback_restores_workspace_and_regrants)
{
	sandbox_fixture_t fixture;
	glaipnir_require_ok(fixture.run("rollback", "", "echo v1> data.txt"));
	{
		auto session = fixture.session("rollback");
		glaipnir_require_ok(session);
		glaipnir_require(session->snapshot("one").has_value());
	}
	glaipnir_require_ok(fixture.run("rollback", "", "echo v2> data.txt"));
	{
		auto session = fixture.session("rollback");
		glaipnir_require_ok(session);
		glaipnir_require(session->rollback("one").has_value());
	}
	glaipnir_check(read_file(fixture.workspace("rollback") / "data.txt") == "v1\r\n");
	auto after = fixture.run("rollback", "", "echo v3> data.txt");
	glaipnir_require_ok(after);
	glaipnir_check(read_file(fixture.workspace("rollback") / "data.txt") == "v3\r\n");
}

glaipnir_test(win_batch_files_are_refused)
{
	sandbox_fixture_t fixture;
	const auto script = fixture.temp.path() / "evil.cmd";
	write_file(script, "@echo hi");
	auto policy = fixture.policy_from("");
	glaipnir_require_ok(policy);
	auto session = fixture.session("batch");
	glaipnir_require_ok(session);
	auto sandbox = c_sandbox::create(std::move(*policy), *session);
	glaipnir_require_ok(sandbox);
	auto result = sandbox->run({path_text(script), "arg & calc"});
	glaipnir_check(!result.has_value());
}

glaipnir_test(win_lpac_mode_runs_system_binaries)
{
	sandbox_fixture_t fixture;
	auto result = fixture.run("lpac", "[sandbox]\nless_privileged = true\n", "echo lpac> out.txt");
	glaipnir_require_ok(result);
	if (result->exit_code != 0)
	{
		glaipnir::test::note(
			"cmd.exe could not run under LPAC on this machine (exit " + std::to_string(result->exit_code) + ")");
		return;
	}
	glaipnir_check(read_file(fixture.workspace("lpac") / "out.txt") == "lpac\r\n");
}

#endif
