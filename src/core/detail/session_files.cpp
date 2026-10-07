#include "core/detail/session_files.hpp"

#include <fstream>

#include "glaipnir/core/c_audit_log.hpp"

glaipnir::core::result_t<void> glaipnir::core::detail::write_session_meta(const std::filesystem::path& directory)
{
	std::ofstream output(directory / session_meta_file_name, std::ios::binary | std::ios::trunc);
	output << "created_at = \"" << utc_timestamp() << "\"\n";
	output.flush();
	if (!output)
	{
		return make_error(error_code::io_error, "cannot write session metadata");
	}
	return ok();
}
