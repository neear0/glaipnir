#include "glaipnir/platform/windows/c_windows_backend.hpp"

#include "platform/windows/detail/backend_support.hpp"
#include "platform/windows/detail/c_attribute_list.hpp"
#include "platform/windows/detail/c_sid.hpp"
#include "platform/windows/detail/exposure_report.hpp"
#include "platform/windows/detail/exposure_scan.hpp"
#include "platform/windows/detail/grant_ledger.hpp"
#include "platform/windows/detail/grant_plan.hpp"
#include "platform/windows/detail/mandatory_label.hpp"
#include "platform/windows/detail/restricted_token.hpp"
#include "platform/windows/detail/sandbox_environment.hpp"
#include "platform/windows/detail/win_util.hpp"

#include <algorithm>
#include <array>
#include <cwctype>
#include <format>
#include <map>
#include <system_error>
#include <vector>

#include "glaipnir/core/path_util.hpp"
#include "glaipnir/platform/windows/command_line.hpp"
#include "glaipnir/platform/windows/path_acl.hpp"

using glaipnir::core::error_code;
using glaipnir::core::make_error;
using glaipnir::core::result_t;

glaipnir::platform::windows::c_windows_backend::c_windows_backend(policy::policy_t policy,
                                                                  policy::isolation_backend mode,
                                                                  std::string session_id, std::string session_key,
                                                                  c_app_container container, std::string sandbox_sid,
                                                                  std::filesystem::path workspace,
                                                                  std::filesystem::path container_folder)
	: policy_(std::move(policy)), mode_(mode), session_id_(std::move(session_id)), session_key_(std::move(session_key)),
	  container_(std::move(container)),
	  sandbox_sid_(std::move(sandbox_sid)), workspace_(std::move(workspace)),
	  container_folder_(std::move(container_folder))
{
}

result_t<glaipnir::platform::windows::c_windows_backend>
glaipnir::platform::windows::c_windows_backend::prepare(const policy::c_policy& policy, std::string_view session_id,
                                                        const std::filesystem::path& session_dir,
                                                        const std::filesystem::path& workspace,
                                                        core::c_audit_log& audit)
{
	const auto& data = policy.data();
	using policy::isolation_backend;
	if (data.backend == isolation_backend::windows_sandbox)
	{
		return make_error(error_code::not_supported,
		                  "the windows_sandbox backend is not implemented yet; use app_container or restricted_token");
	}
	if (data.backend == isolation_backend::process || data.backend == isolation_backend::firecracker)
	{
		return make_error(error_code::not_supported,
		                  "backend '" + std::string{policy::to_string(data.backend)} + "' is Linux-only");
	}
	if (data.network == policy::network_mode::proxy)
	{
		return make_error(error_code::not_supported,
		                  "network.mode = \"proxy\" is not available on Windows yet; use \"none\" or \"unrestricted\"");
	}
	const bool restricted = data.backend == isolation_backend::restricted_token;
	if (restricted && data.network == policy::network_mode::none)
	{
		return make_error(error_code::not_supported,
		                  "the restricted_token backend cannot block network access without administrator rights; "
		                  "set network.mode = \"unrestricted\" or use backend = \"app_container\"");
	}
	if (restricted && data.less_privileged)
	{
		return make_error(error_code::invalid_policy, "sandbox.less_privileged only applies to the app_container backend");
	}
	const auto mode = restricted ? isolation_backend::restricted_token : isolation_backend::app_container;
	const auto key = detail::session_key(session_id, session_dir);

	auto container = c_app_container::create_or_open(detail::container_moniker(key));
	if (!container)
	{
		return std::move(container).error();
	}
	auto folder = container->folder();
	if (!folder)
	{
		return std::move(folder).error();
	}
	std::error_code ec;
	for (const auto* sub : {L"home/AppData/Roaming", L"home/AppData/Local", L"tmp"})
	{
		std::filesystem::create_directories(*folder / sub, ec);
		if (ec)
		{
			return make_error(error_code::io_error, "cannot create sandbox profile directories: " + ec.message(),
			                  ec.value());
		}
	}

	auto sandbox_sid = restricted
		                   ? result_t<detail::c_sid>{detail::c_sid::for_session(key)}
		                   : detail::c_sid::copy_of(container->sid());
	if (!sandbox_sid)
	{
		return std::move(sandbox_sid).error();
	}
	std::vector<detail::c_sid> baseline;
	if (restricted)
	{
		for (const auto text : detail::restricted_baseline_sids)
		{
			auto sid = detail::c_sid::from_string(text);
			if (!sid)
			{
				return std::move(sid).error();
			}
			baseline.push_back(std::move(*sid));
		}
	}
	else
	{
		auto sid = detail::c_sid::from_string(data.less_privileged ? "S-1-15-2-2" : "S-1-15-2-1");
		if (!sid)
		{
			return std::move(sid).error();
		}
		baseline.push_back(std::move(*sid));
	}
	std::vector<void*> baseline_groups;
	for (const auto& sid : baseline)
	{
		baseline_groups.push_back(sid.get());
	}

	detail::grant_plan_input_t plan_input;
	plan_input.sid = sandbox_sid->to_string();
	plan_input.workspace = workspace;
	plan_input.container_folder = *folder;
	plan_input.rules = data.paths;
	plan_input.restricted = restricted;
	std::vector<std::string> notices;
	if (restricted)
	{
		notices.push_back(detail::restricted_token_limits());
	}
	if (restricted && !policy.host().home.empty())
	{
		for (const auto& path : detail::find_exposed_directories(policy.host().home, detail::exposure_scan_depth,
		                                                         baseline_groups))
		{
			const bool granted_on_purpose = std::any_of(data.paths.begin(), data.paths.end(), [&](const auto& rule)
			{
				return core::is_same_or_inside(path, rule.path);
			});
			if (!granted_on_purpose)
			{
				plan_input.exposed.push_back(path);
			}
		}
	}
	if (!plan_input.exposed.empty())
	{
		std::string listed;
		for (const auto& path : plan_input.exposed)
		{
			listed += (listed.empty() ? "" : ", ") + core::to_display_string(path);
		}
		(void)audit.record("exposure." + std::string{policy::to_string(data.exposed_folders)}, listed);
		switch (data.exposed_folders)
		{
		case policy::exposure_handling::refuse:
			return make_error(error_code::invalid_policy, detail::exposure_refusal(plan_input.exposed));
		case policy::exposure_handling::warn:
			notices.push_back(detail::exposure_warning(plan_input.exposed));
			plan_input.exposed.clear();
			break;
		case policy::exposure_handling::deny:
			notices.push_back(detail::exposure_denial(plan_input.exposed));
			break;
		}
	}
	const auto desired = detail::plan_grants(plan_input);

	const auto ledger = session_dir / detail::ledger_file_name;
	const auto recorded = detail::read_ledger(ledger, container->sid_string());
	for (const auto& old : recorded)
	{
		const bool still_wanted = std::any_of(desired.begin(), desired.end(), [&](const auto& want)
		{
			return detail::same_entry(want, old);
		});
		if (!still_wanted)
		{
			auto reverted = detail::revert_entry(old);
			if (!reverted)
			{
				return std::move(reverted).error();
			}
			(void)audit.record("grant.revoke", std::format("{} {}", detail::to_string(old.kind),
			                                               core::to_display_string(old.path)));
		}
	}
	auto written = detail::write_ledger(ledger, desired);
	if (!written)
	{
		return std::move(written).error();
	}

	std::vector<detail::ledger_entry_t> kept;
	for (const auto& want : desired)
	{
		const bool was_recorded = std::any_of(recorded.begin(), recorded.end(), [&](const auto& old)
		{
			return detail::same_entry(want, old);
		});
		std::string outcome_text;
		bool keep = true;
		if (want.kind == detail::ledger_kind::low_label)
		{
			auto changed = detail::apply_low_label(want.path);
			if (!changed)
			{
				(void)audit.record("grant.denied", core::to_display_string(want.path) + ": " + changed.error().message);
				return std::move(changed).error();
			}
			keep = *changed || was_recorded;
			outcome_text = *changed ? "granted" : "unchanged";
		}
		else
		{
			grant_kind kind = grant_kind::read_only;
			switch (want.kind)
			{
			case detail::ledger_kind::read_write: kind = grant_kind::read_write;
				break;
			case detail::ledger_kind::traverse: kind = grant_kind::traverse;
				break;
			case detail::ledger_kind::deny: kind = grant_kind::deny;
				break;
			default: kind = grant_kind::read_only;
				break;
			}
			auto outcome = grant_path_access(want.path, sandbox_sid->get(), kind, baseline_groups);
			if (!outcome && kind == grant_kind::traverse)
			{
				outcome = grant_outcome::skipped;
			}
			if (!outcome)
			{
				(void)audit.record("grant.denied", core::to_display_string(want.path) + ": " + outcome.error().message);
				return std::move(outcome).error();
			}
			keep = *outcome == grant_outcome::granted || *outcome == grant_outcome::unchanged;
			outcome_text = detail::outcome_name(*outcome);
		}
		if (keep)
		{
			kept.push_back(want);
		}
		(void)audit.record("grant.path", std::format("{} {} ({})", detail::to_string(want.kind),
		                                             core::to_display_string(want.path), outcome_text));
	}
	written = detail::write_ledger(ledger, kept);
	if (!written)
	{
		return std::move(written).error();
	}

	(void)audit.record("sandbox.prepare", std::format("backend={} sid={} lpac={} network={} exposed={}",
	                                                  policy::to_string(mode), plan_input.sid, data.less_privileged,
	                                                  policy::to_string(data.network), plan_input.exposed.size()));
	c_windows_backend backend{
		data, mode, std::string{session_id}, key, std::move(*container), plan_input.sid, workspace, std::move(*folder)
	};
	backend.notices_ = std::move(notices);
	return backend;
}

result_t<std::wstring>
glaipnir::platform::windows::c_windows_backend::build_environment(const isolation::launch_spec_t& spec) const
{
	std::map<std::wstring, std::wstring, detail::case_insensitive_less_t> variables;
	for (const auto* name : detail::essential_variables)
	{
		auto value = detail::host_variable(name);
		if (!value.empty())
		{
			variables[name] = std::move(value);
		}
	}
	const auto home = (container_folder_ / "home").native();
	variables[L"USERPROFILE"] = home;
	variables[L"HOME"] = home;
	variables[L"APPDATA"] = (container_folder_ / "home" / "AppData" / "Roaming").native();
	variables[L"LOCALAPPDATA"] = (container_folder_ / "home" / "AppData" / "Local").native();
	variables[L"TEMP"] = (container_folder_ / "tmp").native();
	variables[L"TMP"] = (container_folder_ / "tmp").native();

	for (const auto& [name, value] : spec.environment)
	{
		variables[detail::to_wide(name)] = detail::to_wide(value);
	}
	variables[L"GLAIPNIR_SESSION"] = detail::to_wide(session_id_);
	variables[L"GLAIPNIR_WORKSPACE"] = workspace_.native();

	std::wstring block;
	for (const auto& [name, value] : variables)
	{
		if (value.find(L'\0') != std::wstring::npos)
		{
			return make_error(error_code::invalid_argument,
			                  "environment value for " + detail::from_wide(name) + " contains NUL");
		}
		block += name;
		block += L'=';
		block += value;
		block += L'\0';
	}
	block += L'\0';
	return block;
}

result_t<void> glaipnir::platform::windows::c_windows_backend::start(const isolation::launch_spec_t& spec)
{
	if (process_.valid())
	{
		return make_error(error_code::busy, "sandbox already started");
	}
	if (spec.argv.empty())
	{
		return make_error(error_code::invalid_argument, "no command given");
	}
	const bool restricted = mode_ == policy::isolation_backend::restricted_token;

	std::wstring search_path = detail::host_variable(L"PATH");
	for (const auto& [name, value] : spec.environment)
	{
		if (CompareStringOrdinal(detail::to_wide(name).c_str(), -1, L"PATH", -1, TRUE) == CSTR_EQUAL)
		{
			search_path = detail::to_wide(value);
		}
	}
	auto executable = resolve_executable(detail::to_wide(spec.argv.front()), search_path,
	                                     detail::host_variable(L"PATHEXT"));
	if (!executable)
	{
		return std::move(executable).error();
	}
	auto extension = executable->extension().native();
	std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
	if (extension == L".bat" || extension == L".cmd")
	{
		return make_error(error_code::invalid_argument,
		                  "refusing to launch batch file " + core::to_display_string(*executable) +
		                  " directly; run it explicitly via `cmd /c` if you accept cmd's argument parsing");
	}

	std::vector<std::wstring> wide_argv{executable->native()};
	for (std::size_t i = 1; i < spec.argv.size(); ++i)
	{
		wide_argv.push_back(detail::to_wide(spec.argv[i]));
	}
	auto command_line = build_command_line(wide_argv);
	if (!command_line)
	{
		return std::move(command_line).error();
	}
	auto environment = build_environment(spec);
	if (!environment)
	{
		return std::move(environment).error();
	}

	c_unique_handle token;
	if (restricted)
	{
		auto sid = detail::c_sid::from_string(sandbox_sid_);
		if (!sid)
		{
			return std::move(sid).error();
		}
		auto created = detail::create_restricted_token(sid->get());
		if (!created)
		{
			return std::move(created).error();
		}
		token = std::move(*created);
	}

	auto job = c_job_object::create(session_key_, policy_.limits, policy_.capabilities);
	if (!job)
	{
		return std::move(job).error();
	}

	std::vector<detail::well_known_sid_t> capability_sids;
	std::vector<SID_AND_ATTRIBUTES> capabilities;
	if (!restricted && policy_.network == policy::network_mode::unrestricted)
	{
		detail::well_known_sid_t sid;
		DWORD size = static_cast<DWORD>(sid.bytes.size());
		if (!CreateWellKnownSid(WinCapabilityInternetClientSid, nullptr, sid.bytes.data(), &size))
		{
			return detail::last_error("cannot build internetClient capability");
		}
		capability_sids.push_back(sid);
	}
	for (auto& sid : capability_sids)
	{
		capabilities.push_back({sid.bytes.data(), SE_GROUP_ENABLED});
	}
	SECURITY_CAPABILITIES security{};
	security.AppContainerSid = container_.sid();
	security.Capabilities = capabilities.empty() ? nullptr : capabilities.data();
	security.CapabilityCount = static_cast<DWORD>(capabilities.size());

	std::vector<HANDLE> inherited;
	for (const DWORD which : {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE})
	{
		HANDLE handle = GetStdHandle(which);
		if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
			std::find(inherited.begin(), inherited.end(), handle) != inherited.end())
		{
			continue;
		}
		if (SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
		{
			inherited.push_back(handle);
		}
	}

	HANDLE job_handle = job->handle();
	DWORD64 mitigations = PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON;
	DWORD child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
	DWORD packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

	const bool use_handle_list = !inherited.empty();
	const bool block_children = !policy_.capabilities.child_processes;
	const bool use_lpac = !restricted && policy_.less_privileged;
	const DWORD attribute_count = 2 + (restricted ? 0 : 1) + (use_handle_list ? 1 : 0) + (block_children ? 1 : 0) +
		(use_lpac ? 1 : 0);
	auto attributes = detail::c_attribute_list::create(attribute_count);
	if (!attributes)
	{
		return std::move(attributes).error();
	}
	std::vector<result_t<void>> updates;
	updates.push_back(attributes->set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handle, sizeof(job_handle), "job list"));
	updates.push_back(attributes->set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigations, sizeof(mitigations),
	                                  "mitigation policy"));
	if (!restricted)
	{
		updates.push_back(attributes->set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security, sizeof(security),
		                                  "security capabilities"));
	}
	if (use_handle_list)
	{
		updates.push_back(attributes->set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(),
		                                  inherited.size() * sizeof(HANDLE), "handle list"));
	}
	if (block_children)
	{
		updates.push_back(attributes->set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy,
		                                  sizeof(child_policy), "child process policy"));
	}
	if (use_lpac)
	{
		updates.push_back(attributes->set(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &packages_policy,
		                                  sizeof(packages_policy), "LPAC policy"));
	}
	for (auto& update : updates)
	{
		if (!update)
		{
			return std::move(update).error();
		}
	}

	STARTUPINFOEXW startup{};
	startup.StartupInfo.cb = sizeof(startup);
	startup.lpAttributeList = attributes->get();
	if (use_handle_list)
	{
		startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
		startup.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		startup.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		startup.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	}

	const std::filesystem::path working_directory =
		spec.working_directory.empty() ? workspace_ : spec.working_directory;
	const DWORD creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
	PROCESS_INFORMATION info{};
	const BOOL created = restricted
		                     ? CreateProcessAsUserW(token.get(), executable->c_str(), command_line->data(), nullptr,
		                                            nullptr, use_handle_list ? TRUE : FALSE, creation_flags,
		                                            environment->data(), working_directory.c_str(),
		                                            &startup.StartupInfo, &info)
		                     : CreateProcessW(executable->c_str(), command_line->data(), nullptr, nullptr,
		                                      use_handle_list ? TRUE : FALSE, creation_flags, environment->data(),
		                                      working_directory.c_str(), &startup.StartupInfo, &info);
	if (!created)
	{
		const DWORD code = GetLastError();
		std::string hint;
		if (code == ERROR_ACCESS_DENIED)
		{
			hint = "; the sandbox cannot read " + core::to_display_string(*executable) +
				" or its directory. Add the program's install directory to filesystem.read";
		}
		return detail::win32_error("cannot start " + core::to_display_string(*executable) + hint, code);
	}
	CloseHandle(info.hThread);
	process_.reset(info.hProcess);
	job_.emplace(std::move(*job));
	started_at_ = std::chrono::steady_clock::now();
	return core::ok();
}

result_t<glaipnir::isolation::sandbox_result_t> glaipnir::platform::windows::c_windows_backend::wait()
{
	if (!process_.valid() || !job_)
	{
		return make_error(error_code::invalid_argument, "sandbox was not started");
	}
	isolation::sandbox_result_t result;

	const auto wall_limit = std::chrono::seconds{policy_.limits.wall_timeout_seconds};
	bool timed_out = false;
	while (true)
	{
		DWORD wait_ms = INFINITE;
		if (wall_limit.count() != 0)
		{
			const auto remaining = wall_limit - (std::chrono::steady_clock::now() - started_at_);
			const auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
			if (remaining_ms <= 0)
			{
				timed_out = true;
				break;
			}
			wait_ms = static_cast<DWORD>(std::min<long long>(remaining_ms, 24LL * 3600 * 1000));
		}
		const DWORD status = WaitForSingleObject(process_.get(), wait_ms);
		if (status == WAIT_OBJECT_0)
		{
			break;
		}
		if (status != WAIT_TIMEOUT)
		{
			return detail::last_error("waiting for sandboxed process failed");
		}
	}
	if (timed_out)
	{
		(void)job_->terminate(detail::timeout_exit_code);
		WaitForSingleObject(process_.get(), INFINITE);
		result.reason = isolation::termination_reason::wall_timeout;
	}

	DWORD exit_code = 0;
	GetExitCodeProcess(process_.get(), &exit_code);
	result.exit_code = static_cast<int>(exit_code);
	result.wall_time = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - started_at_);

	if (auto usage = job_->usage())
	{
		result.cpu_time = usage->user_time + usage->kernel_time;
		result.peak_memory_bytes = usage->peak_memory_bytes;
		const auto cpu_limit = std::chrono::seconds{policy_.limits.cpu_timeout_seconds};
		if (!timed_out && cpu_limit.count() != 0 && usage->user_time >= cpu_limit)
		{
			result.reason = isolation::termination_reason::cpu_timeout;
		}
	}
	if (terminated_->load())
	{
		result.reason = isolation::termination_reason::terminated;
	}
	(void)job_->terminate(exit_code);
	process_.reset();
	return result;
}

result_t<void> glaipnir::platform::windows::c_windows_backend::pause() const
{
	if (!job_)
	{
		return make_error(error_code::invalid_argument, "sandbox was not started");
	}
	return job_->suspend();
}

result_t<void> glaipnir::platform::windows::c_windows_backend::resume() const
{
	if (!job_)
	{
		return make_error(error_code::invalid_argument, "sandbox was not started");
	}
	return job_->resume();
}

result_t<void> glaipnir::platform::windows::c_windows_backend::terminate() const
{
	if (!job_)
	{
		return make_error(error_code::invalid_argument, "sandbox was not started");
	}
	terminated_->store(true);
	return job_->terminate(detail::terminated_exit_code);
}

result_t<void> glaipnir::platform::windows::c_windows_backend::cleanup(std::string_view session_id,
                                                                       const std::filesystem::path& session_dir)
{
	const auto moniker = detail::container_moniker(detail::session_key(session_id, session_dir));
	const auto ledger = session_dir / detail::ledger_file_name;
	std::error_code ec;
	if (std::filesystem::exists(ledger, ec))
	{
		auto container = c_app_container::create_or_open(moniker);
		if (!container)
		{
			return std::move(container).error();
		}
		for (const auto& entry : detail::read_ledger(ledger, container->sid_string()))
		{
			if (core::is_same_or_inside(entry.path, session_dir))
			{
				continue;
			}
			auto reverted = detail::revert_entry(entry);
			if (!reverted)
			{
				return reverted;
			}
		}
	}
	std::filesystem::remove(ledger, ec);
	return c_app_container::remove(moniker);
}

result_t<void> glaipnir::platform::windows::c_windows_backend::pause_running(std::string_view session_id,
	const std::filesystem::path& session_dir)
{
	auto job = c_job_object::open(detail::session_key(session_id, session_dir));
	if (!job)
	{
		return std::move(job).error();
	}
	return job->suspend();
}

result_t<void> glaipnir::platform::windows::c_windows_backend::resume_running(std::string_view session_id,
	const std::filesystem::path& session_dir)
{
	auto job = c_job_object::open(detail::session_key(session_id, session_dir));
	if (!job)
	{
		return std::move(job).error();
	}
	return job->resume();
}

result_t<void> glaipnir::platform::windows::c_windows_backend::terminate_running(std::string_view session_id,
	const std::filesystem::path& session_dir)
{
	auto job = c_job_object::open(detail::session_key(session_id, session_dir));
	if (!job)
	{
		return std::move(job).error();
	}
	return job->terminate(detail::terminated_exit_code);
}
