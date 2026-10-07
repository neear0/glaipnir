#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "glaipnir/core/c_session.hpp"
#include "glaipnir/core/error.hpp"
#include "glaipnir/isolation/isolation_types.hpp"
#include "glaipnir/platform/platform.hpp"
#include "glaipnir/policy/c_policy.hpp"

namespace glaipnir::core
{
	class c_sandbox
	{
	public:
		static result_t<c_sandbox> create(policy::c_policy policy, c_session& session);

		result_t<void> start(const std::vector<std::string>& argv, const std::filesystem::path& working_directory = {});

		result_t<isolation::sandbox_result_t> wait();

		result_t<isolation::sandbox_result_t> run(const std::vector<std::string>& argv,
		                                          const std::filesystem::path& working_directory = {});

		result_t<void> pause();
		result_t<void> resume();
		result_t<void> terminate() const;

		const policy::c_policy& policy() const noexcept { return policy_; }

		const std::vector<std::string>& notices() const noexcept { return backend_.notices(); }

	private:
		c_sandbox(policy::c_policy policy, c_session& session, platform::platform_backend backend);

		policy::c_policy policy_;
		c_session* session_;
		platform::platform_backend backend_;
	};
}
