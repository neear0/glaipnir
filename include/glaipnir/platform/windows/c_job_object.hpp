#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "glaipnir/platform/windows/c_unique_handle.hpp"
#include "glaipnir/policy/policy_types.hpp"

namespace glaipnir::platform::windows
{
	struct job_usage_t
	{
		std::chrono::milliseconds user_time{0};
		std::chrono::milliseconds kernel_time{0};
		std::uint64_t peak_memory_bytes = 0;
		std::uint32_t active_processes = 0;
	};

	class c_job_object
	{
	public:
		static core::result_t<c_job_object> create(std::string_view session_id, const policy::resource_limit_t& limits,
		                                           const policy::capability_t& capabilities);

		static core::result_t<c_job_object> open(std::string_view session_id);

		void* handle() const noexcept { return handle_.get(); }

		core::result_t<void> terminate(unsigned exit_code) const;

		core::result_t<void> suspend() const;

		core::result_t<void> resume() const;

		core::result_t<job_usage_t> usage() const;

		core::result_t<std::vector<std::uint32_t>> process_ids() const;

	private:
		explicit c_job_object(c_unique_handle handle) : handle_(std::move(handle))
		{
		}

		c_unique_handle handle_;
	};
}
