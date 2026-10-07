#pragma once

#include <string>
#include <string_view>

#include "glaipnir/core/error.hpp"

namespace glaipnir::cli::detail
{
	inline constexpr std::string_view usage_text = R"(glaipnir - deny-by-default sandbox for AI agents

usage:
  glaipnir run [--policy FILE] [--session ID] [--cwd DIR] -- COMMAND [ARGS...]
  glaipnir policy check FILE
  glaipnir session list
  glaipnir session create|delete|pause|resume|kill ID
  glaipnir session fork SOURCE_ID NEW_ID
  glaipnir snapshot list SESSION
  glaipnir snapshot create|rollback|delete SESSION LABEL
  glaipnir audit verify SESSION
  glaipnir version

global options:
  --state-dir DIR   where sessions, snapshots and audit logs live
                    (default: %LOCALAPPDATA%\glaipnir, or $GLAIPNIR_STATE_DIR)

Without --policy the sandbox gets nothing: no paths beyond its workspace, no network,
no inherited environment, no child processes. Without --session the run uses a throwaway
session that is deleted afterwards.
)";

	void print_error(const core::error_t& error);

	int fail(const core::error_t& error);

	int usage_error(std::string_view message);

	std::string random_suffix();
}
