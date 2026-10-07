#pragma once

#include <cstdint>
#include <filesystem>
#include <string_view>

#include "glaipnir/core/error.hpp"

#ifdef _WIN32
#include "glaipnir/platform/windows/c_windows_backend.hpp"
#endif

namespace glaipnir::platform
{
#ifdef _WIN32
	using platform_backend = windows::c_windows_backend;
#endif

	class c_session_lock
	{
	public:
		static core::result_t<c_session_lock> acquire(const std::filesystem::path& path);

		c_session_lock(c_session_lock&& other) noexcept;
		c_session_lock& operator=(c_session_lock&& other) noexcept;
		c_session_lock(const c_session_lock&) = delete;
		c_session_lock& operator=(const c_session_lock&) = delete;
		~c_session_lock();

	private:
		explicit c_session_lock(std::intptr_t native) : native_(native)
		{
		}

		void release() noexcept;

		std::intptr_t native_ = -1;
	};

	std::filesystem::path default_state_root();

	core::result_t<void> cleanup_session(std::string_view session_id, const std::filesystem::path& session_dir);

	core::result_t<void> pause_session(std::string_view session_id, const std::filesystem::path& session_dir);
	core::result_t<void> resume_session(std::string_view session_id, const std::filesystem::path& session_dir);
	core::result_t<void> terminate_session(std::string_view session_id, const std::filesystem::path& session_dir);
}
