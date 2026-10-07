#include "support/test_harness.hpp"

#include "glaipnir/core/path_util.hpp"
#include "glaipnir/policy/c_policy.hpp"
#include "glaipnir/policy/c_toml_reader.hpp"
#include "support/fake_host.hpp"

using glaipnir::policy::c_policy;
using glaipnir::policy::c_toml_reader;
using glaipnir::test::fake_host_t;
using glaipnir::test::policy_parses;

glaipnir_test(toml_subset_parses_supported_forms)
{
	auto reader = c_toml_reader::parse(R"(
# comment
top = 1
[a]
s = "x\ty\u00e9"   # trailing comment
l = 'C:\literal\path'
n = -1_000
b = true
list = [
  "one",  # inside array
  'two',
]
[a.b]
empty = []
)");
	glaipnir_require_ok(reader);
	const auto& entries = reader->entries();
	glaipnir_check(std::get<std::int64_t>(entries.at("top").data) == 1);
	glaipnir_check(std::get<std::string>(entries.at("a.s").data) == "x\ty\xc3\xa9");
	glaipnir_check(std::get<std::string>(entries.at("a.l").data) == "C:\\literal\\path");
	glaipnir_check(std::get<std::int64_t>(entries.at("a.n").data) == -1000);
	glaipnir_check(std::get<bool>(entries.at("a.b").data));
	glaipnir_check(
		(std::get<std::vector<std::string>>(entries.at("a.list").data) == std::vector<std::string>{"one", "two"}));
	glaipnir_check(std::get<std::vector<std::string>>(entries.at("a.b.empty").data).empty());
}

glaipnir_test(toml_subset_rejects_ambiguous_input)
{
	glaipnir_check(!c_toml_reader::parse("a = 1\na = 2").has_value());
	glaipnir_check(!c_toml_reader::parse("[t]\n[t]").has_value());
	glaipnir_check(!c_toml_reader::parse("a.b = 1").has_value());
	glaipnir_check(!c_toml_reader::parse("a = {b = 1}").has_value());
	glaipnir_check(!c_toml_reader::parse("a = 1.5").has_value());
	glaipnir_check(!c_toml_reader::parse("a = 0x10").has_value());
	glaipnir_check(!c_toml_reader::parse("a = 007").has_value());
	glaipnir_check(!c_toml_reader::parse("a = \"C:\\Users\"").has_value());
	glaipnir_check(!c_toml_reader::parse("a = \"unterminated").has_value());
	glaipnir_check(!c_toml_reader::parse("a = [1, 2]").has_value());
	glaipnir_check(!c_toml_reader::parse("a = true false").has_value());
	glaipnir_check(!c_toml_reader::parse("[[arr]]").has_value());
	glaipnir_check(!c_toml_reader::parse("a = 99999999999999999999").has_value());
}

glaipnir_test(policy_defaults_deny_everything)
{
	const auto& data = c_policy::deny_all().data();
	glaipnir_check(data.paths.empty());
	glaipnir_check(data.network == glaipnir::policy::network_mode::none);
	glaipnir_check(data.env.pass.empty() && data.env.set.empty());
	glaipnir_check(!data.capabilities.child_processes);
	glaipnir_check(!data.capabilities.clipboard_read && !data.capabilities.clipboard_write);
}

glaipnir_test(policy_full_example_round_trips)
{
	fake_host_t fake;
	const std::string text = R"(
[sandbox]
name = "agent"
backend = "app_container"

[filesystem]
read = [")" + fake.at("tools") + R"("]
write = ["${cwd}"]

[network]
mode = "proxy"
allow = ["api.anthropic.com", "*.github.com:22"]

[env]
pass = ["PATH"]
[env.set]
LANG = "C.UTF-8"

[limits]
memory_mb = 1024
max_processes = 32
cpu_percent = 50
wall_timeout_s = 600

[capabilities]
child_processes = true
)";
	auto policy = c_policy::parse(text, fake.host);
	glaipnir_require_ok(policy);
	const auto& data = policy->data();
	glaipnir_check(data.name == "agent");
	glaipnir_require(data.paths.size() == 2);
	glaipnir_check(data.paths[1].access == glaipnir::policy::access_mode::read_write);
	glaipnir_check(glaipnir::core::is_same_or_inside(data.paths[1].path, fake.host.cwd) &&
		glaipnir::core::is_same_or_inside(fake.host.cwd, data.paths[1].path));
	glaipnir_require(data.net_rules.size() == 2);
	glaipnir_check(data.net_rules[0].port == 443);
	glaipnir_check(data.net_rules[1].host_pattern == "*.github.com" && data.net_rules[1].port == 22);
	glaipnir_check(data.limits.memory_bytes == 1024ull * 1024 * 1024);
	glaipnir_check(data.capabilities.child_processes);

	auto reparsed = c_policy::parse(policy->to_toml(), fake.host);
	glaipnir_require_ok(reparsed);
	glaipnir_check(reparsed->digest() == policy->digest());
}

glaipnir_test(policy_rejects_dangerous_paths)
{
	fake_host_t fake;
	const auto with_read = [&](const std::string& path)
	{
		return "[filesystem]\nread = [\"" + path + "\"]\n";
	};
	glaipnir_check(!policy_parses(with_read("${home}"), fake.host));
	glaipnir_check(!policy_parses(with_read(fake.at("")), fake.host));
	glaipnir_check(!policy_parses(with_read("${home}/.ssh"), fake.host));
	glaipnir_check(!policy_parses(with_read("${home}/AppData/Roaming"), fake.host));
	glaipnir_check(!policy_parses(with_read(fake.at("state")), fake.host));
	glaipnir_check(!policy_parses(with_read("${home}/does-not-exist"), fake.host));
	glaipnir_check(!policy_parses(with_read("relative/path"), fake.host));
	glaipnir_check(!policy_parses(with_read("${env:SECRET}"), fake.host));
#ifdef _WIN32
	glaipnir_check(!policy_parses(with_read("C:/"), fake.host));
#endif
	glaipnir_check(policy_parses(with_read("${home}/code/project"), fake.host));
}

glaipnir_test(policy_rejects_secrets_and_typos)
{
	fake_host_t fake;
	glaipnir_check(!policy_parses("[env]\npass = [\"GITHUB_TOKEN\"]", fake.host));
	glaipnir_check(!policy_parses("[env]\npass = [\"AWS_SECRET_ACCESS_KEY\"]", fake.host));
	glaipnir_check(!policy_parses("[env.set]\nANTHROPIC_API_KEY = \"sk-x\"", fake.host));
	glaipnir_check(!policy_parses("[env.set]\nGLAIPNIR_SESSION = \"x\"", fake.host));
	glaipnir_check(!policy_parses("[env]\npass = [\"PATH\", \"PATH\"]", fake.host));
	glaipnir_check(!policy_parses("[capabilities]\nchild_process = true", fake.host));
	glaipnir_check(!policy_parses("[capabilites]\nchild_processes = true", fake.host));
	glaipnir_check(!policy_parses("[network]\nmode = \"proxy\"", fake.host));
	glaipnir_check(!policy_parses("[network]\nallow = [\"example.com\"]", fake.host));
	glaipnir_check(!policy_parses("[network]\nmode = \"proxy\"\nallow = [\"169.254.169.254\"]", fake.host));
	glaipnir_check(!policy_parses("[network]\nmode = \"proxy\"\nallow = [\"Example.com\"]", fake.host));
	glaipnir_check(!policy_parses("[limits]\ncpu_percent = 150", fake.host));
	glaipnir_check(!policy_parses("[limits]\nmemory_mb = -1", fake.host));
	glaipnir_check(!policy_parses("[sandbox]\nbackend = \"docker\"", fake.host));
	glaipnir_check(glaipnir::policy::looks_like_secret_name("my_api_key"));
	glaipnir_check(!glaipnir::policy::looks_like_secret_name("PATH"));
	glaipnir_check(!glaipnir::policy::looks_like_secret_name("KEYBOARD_LAYOUT"));
}
