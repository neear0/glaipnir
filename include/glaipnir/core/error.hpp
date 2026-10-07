#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace glaipnir::core
{
	enum class error_code
	{
		invalid_argument,
		invalid_policy,
		parse_error,
		not_found,
		already_exists,
		io_error,
		permission_denied,
		platform_error,
		not_supported,
		busy,
		integrity_error,
	};

	struct error_t
	{
		error_code code = error_code::platform_error;
		std::string message;
		long native_code = 0;
	};

	std::string_view to_string(error_code code) noexcept;

	std::string describe(const error_t& error);

	inline error_t make_error(error_code code, std::string message, long native_code = 0)
	{
		return error_t{code, std::move(message), native_code};
	}

	template <typename value_type>
	struct [[nodiscard]] result_t
	{
		result_t(value_type value) : storage_(std::in_place_index<0>, std::move(value))
		{
		}

		result_t(error_t error) : storage_(std::in_place_index<1>, std::move(error))
		{
		}

		bool has_value() const noexcept { return storage_.index() == 0; }
		explicit operator bool() const noexcept { return has_value(); }

		value_type& value() & { return std::get<0>(storage_); }
		const value_type& value() const & { return std::get<0>(storage_); }
		value_type&& value() && { return std::get<0>(std::move(storage_)); }

		const error_t& error() const & { return std::get<1>(storage_); }
		error_t&& error() && { return std::get<1>(std::move(storage_)); }

		value_type* operator->() { return &value(); }
		const value_type* operator->() const { return &value(); }
		value_type& operator*() & { return value(); }
		const value_type& operator*() const & { return value(); }

	private:
		std::variant<value_type, error_t> storage_;
	};

	template <>
	struct [[nodiscard]] result_t<void>
	{
		result_t() = default;

		result_t(error_t error) : error_(std::move(error))
		{
		}

		bool has_value() const noexcept { return !error_.has_value(); }
		explicit operator bool() const noexcept { return has_value(); }

		const error_t& error() const & { return *error_; }
		error_t&& error() && { return std::move(*error_); }

	private:
		std::optional<error_t> error_;
	};

	inline result_t<void> ok() { return {}; }
}
