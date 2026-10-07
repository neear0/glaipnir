#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "glaipnir/core/error.hpp"
#include "platform/windows/detail/win_util.hpp"

namespace glaipnir::platform::windows::detail
{
	class c_attribute_list
	{
	public:
		static core::result_t<c_attribute_list> create(DWORD count);

		c_attribute_list(c_attribute_list&& other) noexcept;
		c_attribute_list& operator=(c_attribute_list&&) = delete;
		c_attribute_list(const c_attribute_list&) = delete;
		c_attribute_list& operator=(const c_attribute_list&) = delete;
		~c_attribute_list();

		LPPROC_THREAD_ATTRIBUTE_LIST get() noexcept;

		core::result_t<void> set(DWORD_PTR attribute, void* value, SIZE_T size, std::string_view what);

	private:
		c_attribute_list() = default;

		std::vector<std::uint8_t> storage_;
		bool initialized_ = false;
	};
}
