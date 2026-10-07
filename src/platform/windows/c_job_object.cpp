#include "glaipnir/platform/windows/c_job_object.hpp"

#include "platform/windows/detail/job_support.hpp"

#include <algorithm>
#include <set>

using glaipnir::core::error_code;
using glaipnir::core::result_t;

result_t<glaipnir::platform::windows::c_job_object>
glaipnir::platform::windows::c_job_object::create(std::string_view session_id, const policy::resource_limit_t& limits,
                                                  const policy::capability_t& capabilities)
{
	c_unique_handle job{CreateJobObjectW(nullptr, detail::job_name(session_id).c_str())};
	if (!job.valid())
	{
		return detail::last_error("cannot create job object");
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		return core::make_error(error_code::busy,
		                        "session '" + std::string{session_id} + "' already has a running sandbox");
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended{};
	auto& basic = extended.BasicLimitInformation;
	basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	if (limits.memory_bytes != 0)
	{
		basic.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
		extended.JobMemoryLimit = static_cast<SIZE_T>(limits.memory_bytes);
	}
	const std::uint32_t process_limit = capabilities.child_processes ? limits.max_processes : 1;
	if (process_limit != 0)
	{
		basic.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
		basic.ActiveProcessLimit = process_limit;
	}
	if (limits.cpu_timeout_seconds != 0)
	{
		basic.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
		basic.PerJobUserTimeLimit.QuadPart = static_cast<LONGLONG>(limits.cpu_timeout_seconds *
			detail::ticks_per_second);
	}
	if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &extended, sizeof(extended)))
	{
		return detail::last_error("cannot set job limits");
	}

	if (limits.cpu_percent != 0 && limits.cpu_percent < 100)
	{
		JOBOBJECT_CPU_RATE_CONTROL_INFORMATION rate{};
		rate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
		rate.CpuRate = limits.cpu_percent * 100;
		if (!SetInformationJobObject(job.get(), JobObjectCpuRateControlInformation, &rate, sizeof(rate)))
		{
			return detail::last_error("cannot set job CPU rate");
		}
	}

	JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
	ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
	if (!capabilities.desktop_ui)
	{
		ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_GLOBALATOMS;
	}
	if (!capabilities.clipboard_read)
	{
		ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
	}
	if (!capabilities.clipboard_write)
	{
		ui.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
	}
	if (!SetInformationJobObject(job.get(), JobObjectBasicUIRestrictions, &ui, sizeof(ui)))
	{
		return detail::last_error("cannot set job UI restrictions");
	}
	return c_job_object{std::move(job)};
}

result_t<glaipnir::platform::windows::c_job_object>
glaipnir::platform::windows::c_job_object::open(std::string_view session_id)
{
	c_unique_handle job{
		OpenJobObjectW(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE, FALSE, detail::job_name(session_id).c_str())
	};
	if (!job.valid())
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			return core::make_error(error_code::not_found, "session '" + std::string{session_id} + "' is not running");
		}
		return detail::last_error("cannot open job of session '" + std::string{session_id} + "'");
	}
	return c_job_object{std::move(job)};
}

result_t<void> glaipnir::platform::windows::c_job_object::terminate(unsigned exit_code) const
{
	if (!TerminateJobObject(handle_.get(), exit_code))
	{
		return detail::last_error("cannot terminate job");
	}
	return core::ok();
}

result_t<std::vector<std::uint32_t>> glaipnir::platform::windows::c_job_object::process_ids() const
{
	std::vector<std::uint8_t> buffer(sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 64 * sizeof(ULONG_PTR));
	while (true)
	{
		auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buffer.data());
		if (QueryInformationJobObject(handle_.get(), JobObjectBasicProcessIdList, list,
		                              static_cast<DWORD>(buffer.size()),
		                              nullptr))
		{
			std::vector<std::uint32_t> ids;
			for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i)
			{
				ids.push_back(static_cast<std::uint32_t>(list->ProcessIdList[i]));
			}
			return ids;
		}
		if (GetLastError() != ERROR_MORE_DATA || buffer.size() > (1u << 24))
		{
			return detail::last_error("cannot list job processes");
		}
		buffer.resize(buffer.size() * 2);
	}
}

result_t<void> glaipnir::platform::windows::c_job_object::suspend() const
{
	std::set<DWORD> frozen;
	for (int pass = 0; pass < 8; ++pass)
	{
		auto ids = process_ids();
		if (!ids)
		{
			return std::move(ids).error();
		}
		std::set<DWORD> fresh;
		for (const auto id : *ids)
		{
			if (!frozen.contains(id))
			{
				fresh.insert(id);
			}
		}
		if (fresh.empty())
		{
			return core::ok();
		}
		detail::for_each_thread(fresh, [](HANDLE thread) { SuspendThread(thread); });
		frozen.insert(fresh.begin(), fresh.end());
	}
	return core::make_error(error_code::busy, "job kept spawning processes while being suspended");
}

result_t<void> glaipnir::platform::windows::c_job_object::resume() const
{
	auto ids = process_ids();
	if (!ids)
	{
		return std::move(ids).error();
	}
	const std::set<DWORD> pids(ids->begin(), ids->end());
	detail::for_each_thread(pids, [](HANDLE thread) { ResumeThread(thread); });
	return core::ok();
}

result_t<glaipnir::platform::windows::job_usage_t> glaipnir::platform::windows::c_job_object::usage() const
{
	JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
	if (!QueryInformationJobObject(handle_.get(), JobObjectBasicAccountingInformation, &accounting, sizeof(accounting),
	                               nullptr))
	{
		return detail::last_error("cannot query job accounting");
	}
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended{};
	if (!QueryInformationJobObject(handle_.get(), JobObjectExtendedLimitInformation, &extended, sizeof(extended),
	                               nullptr))
	{
		return detail::last_error("cannot query job memory");
	}
	job_usage_t usage;
	usage.user_time = detail::ticks_to_ms(accounting.TotalUserTime.QuadPart);
	usage.kernel_time = detail::ticks_to_ms(accounting.TotalKernelTime.QuadPart);
	usage.peak_memory_bytes = extended.PeakJobMemoryUsed;
	usage.active_processes = accounting.ActiveProcesses;
	return usage;
}
