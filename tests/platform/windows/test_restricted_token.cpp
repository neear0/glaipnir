#ifdef _WIN32

#include "support/test_harness.hpp"

#include "glaipnir/core/c_session.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/platform/windows/command_line.hpp"
#include "support/sandbox_fixture.hpp"

using glaipnir::test::command_output;
using glaipnir::test::path_text;
using glaipnir::test::read_file;
using glaipnir::test::restricted_policy;
using glaipnir::test::sandbox_fixture_t;
using glaipnir::test::write_file;

glaipnir_test(win_restricted_runs_with_nul_and_workspace)
{
	sandbox_fixture_t fixture;
	fixture.use_fake_home();
	auto result = fixture.run("rt-basic", restricted_policy(), "echo hidden> NUL && echo visible> out.txt");
	glaipnir_require_ok(result);
	glaipnir_check(result->exit_code == 0);
	glaipnir_check(read_file(fixture.workspace("rt-basic") / "out.txt") == "visible\r\n");
}

glaipnir_test(win_restricted_refuses_unenforceable_policies)
{
	sandbox_fixture_t fixture;
	fixture.use_fake_home();
	auto no_network = fixture.run("rt-refuse", "[sandbox]\nbackend = \"restricted_token\"\n", "echo x");
	glaipnir_check(!no_network.has_value() && no_network.error().code == glaipnir::core::error_code::not_supported);
	auto lpac = fixture.run("rt-refuse",
	                        "[sandbox]\nbackend = \"restricted_token\"\nless_privileged = true\n"
	                        "[network]\nmode = \"unrestricted\"\n", "echo x");
	glaipnir_check(!lpac.has_value());
}

glaipnir_test(win_restricted_cannot_read_profile_or_write_outside)
{
	sandbox_fixture_t fixture;
	fixture.use_fake_home();
	const auto host_dir = fixture.temp.path() / "host-data";
	std::filesystem::create_directories(host_dir);
	write_file(host_dir / "secret.txt", "TOP-SECRET");

	auto read = fixture.run("rt-escape", restricted_policy(),
	                        "type " + path_text(host_dir / "secret.txt") + " > out.txt 2>&1");
	glaipnir_require_ok(read);
	glaipnir_check(read_file(fixture.workspace("rt-escape") / "out.txt").find("TOP-SECRET") == std::string::npos);

	auto write = fixture.run("rt-escape", restricted_policy(), "echo pwned> " + path_text(host_dir / "new.txt"));
	glaipnir_require_ok(write);
	glaipnir_check(!std::filesystem::exists(host_dir / "new.txt"));
}

glaipnir_test(win_restricted_runs_absolute_paths_and_children)
{
	sandbox_fixture_t fixture;
	fixture.use_fake_home();
	auto result = fixture.run("rt-children", restricted_policy("[capabilities]\nchild_processes = true\n"),
	                          std::string{glaipnir::test::cmd_exe} + " /d /c echo nested> nested.txt");
	glaipnir_require_ok(result);
	glaipnir_check(read_file(fixture.workspace("rt-children") / "nested.txt") == "nested\r\n");
}

glaipnir_test(win_restricted_git_repository_workflow)
{
	const auto host_path = glaipnir::core::from_utf8(glaipnir::core::host_env("PATH")).native();
	if (!glaipnir::platform::windows::resolve_executable(L"git", host_path, L".EXE"))
	{
		glaipnir::test::note("git not found on PATH; skipping");
		return;
	}
	sandbox_fixture_t fixture;
	fixture.use_fake_home();
	auto result = fixture.run("rt-git",
	                          restricted_policy("[env]\npass = [\"PATH\"]\n[capabilities]\nchild_processes = true\n"),
	                          "git init -q repo && cd repo && echo a> f && git add f && "
	                          "git -c user.name=t -c user.email=t@t commit -qm first && "
	                          "git log --format=%s > ..\\log.txt && git status --porcelain >> ..\\log.txt");
	glaipnir_require_ok(result);
	glaipnir_check(result->exit_code == 0);
	glaipnir_check(read_file(fixture.workspace("rt-git") / "log.txt") == "first\n");
}

glaipnir_test(win_restricted_exposed_home_folders_follow_the_policy_choice)
{
	sandbox_fixture_t fixture;
	const auto home = fixture.use_fake_home();
	const auto exposed = home / "Desktop";
	const auto elsewhere = fixture.temp.path() / "elsewhere";
	for (const auto& dir : {exposed, elsewhere})
	{
		std::filesystem::create_directories(dir);
		write_file(dir / "doc.txt", "PRIVATE-DOC");
		command_output("icacls \"" + path_text(dir) + "\" /grant *S-1-5-32-545:(OI)(CI)R");
	}
	const auto policy_with = [](const std::string& choice)
	{
		return "[sandbox]\nbackend = \"restricted_token\"\nexposed_folders = \"" + choice +
			"\"\n[network]\nmode = \"unrestricted\"\n";
	};
	const auto read_doc = "type " + path_text(exposed / "doc.txt") + " > out.txt 2>&1";
	const auto output = fixture.workspace("rt-exposed") / "out.txt";

	auto refused = fixture.run("rt-exposed", restricted_policy(), read_doc);
	glaipnir_require(!refused.has_value());
	glaipnir_check(refused.error().message.find(glaipnir::core::to_display_string(exposed)) != std::string::npos);
	glaipnir_check(!std::filesystem::exists(output));

	auto warned = fixture.run("rt-exposed", policy_with("warn"), read_doc);
	glaipnir_require_ok(warned);
	glaipnir_check(read_file(output).find("PRIVATE-DOC") != std::string::npos);

	auto denied = fixture.run("rt-exposed", policy_with("deny"), read_doc);
	glaipnir_require_ok(denied);
	glaipnir_check(read_file(output).find("PRIVATE-DOC") == std::string::npos);
	glaipnir_check(command_output("icacls \"" + path_text(exposed) + "\"").find("S-1-9-") != std::string::npos);

	auto outside_home = fixture.run("rt-exposed", policy_with("deny"),
	                                "type " + path_text(elsewhere / "doc.txt") + " > out.txt 2>&1");
	glaipnir_require_ok(outside_home);
	glaipnir_check(read_file(output).find("PRIVATE-DOC") != std::string::npos);

	auto back_to_warn = fixture.run("rt-exposed", policy_with("warn"), read_doc);
	glaipnir_require_ok(back_to_warn);
	glaipnir_check(command_output("icacls \"" + path_text(exposed) + "\"").find("S-1-9-") == std::string::npos);

	glaipnir_require_ok(fixture.run("rt-exposed", policy_with("deny"), read_doc));
	glaipnir_require(glaipnir::core::c_session::destroy(fixture.state_root(), "rt-exposed").has_value());
	glaipnir_check(command_output("icacls \"" + path_text(exposed) + "\"").find("S-1-9-") == std::string::npos);
}

glaipnir_test(win_restricted_write_paths_are_labeled_until_cleanup)
{
	sandbox_fixture_t fixture;
	fixture.use_fake_home();
	const auto shared = fixture.temp.path() / "shared";
	std::filesystem::create_directories(shared);
	auto written = fixture.run("rt-label",
	                           restricted_policy("[filesystem]\nwrite = ['" + path_text(shared) + "']\n"),
	                           "echo ok> " + path_text(shared / "file.txt"));
	glaipnir_require_ok(written);
	glaipnir_check(read_file(shared / "file.txt") == "ok\r\n");
	glaipnir_check(command_output("icacls \"" + path_text(shared) + "\"").find("Low Mandatory Level") !=
		std::string::npos);

	glaipnir_require(glaipnir::core::c_session::destroy(fixture.state_root(), "rt-label").has_value());
	const auto after = command_output("icacls \"" + path_text(shared) + "\"");
	glaipnir_check(after.find("Low Mandatory Level") == std::string::npos);
	glaipnir_check(after.find("S-1-9-") == std::string::npos);
	glaipnir_check(command_output("icacls \"" + path_text(fixture.temp.path()) + "\"").find("S-1-9-") ==
		std::string::npos);
}

#endif
