#include "platform/windows/detail/exposure_report.hpp"

#include "glaipnir/core/path_util.hpp"

std::string glaipnir::platform::windows::detail::exposure_refusal(const std::vector<std::filesystem::path>& exposed)
{
	std::string text =
		"the restricted_token backend would let the sandboxed program READ these folders in your user profile:\n";
	for (const auto& path : exposed)
	{
		text += "    " + core::to_display_string(path) + "\n";
	}
	text +=
		"\n"
		"Why: restricted_token runs the program as a reduced copy of your own Windows account. Windows needs the\n"
		"\"Users\" group to stay in that copy, otherwise programs cannot even start. Every folder that lets \"Users\"\n"
		"(or \"Everyone\") read it is therefore readable by the sandbox. Personal folders do not allow that by\n"
		"default; the folders above were given this permission at some point, by you or by some software.\n"
		"\n"
		"No permissions were changed. Pick one option and run again:\n"
		"  1. Remove the extra permission from the folder (Properties > Security, or\n"
		"     icacls \"<folder>\" /remove:g *S-1-5-32-545). Safest, but other programs or accounts on this PC\n"
		"     that rely on reading the folder will lose access too.\n"
		"  2. Let glaipnir block the folders: add  exposed_folders = \"deny\"  under [sandbox]. glaipnir adds a\n"
		"     deny rule for this session to each folder and removes it when you delete the session. Windows has\n"
		"     to update every file inside, so this is slow for big folders, and if glaipnir is killed the rule\n"
		"     stays until you run `glaipnir session delete`.\n"
		"  3. Accept the risk: add  exposed_folders = \"warn\"  under [sandbox]. The program can read the folders.\n"
		"  4. Use backend = \"app_container\" instead. It does not have this problem, but some tools fail in it\n"
		"     (for example anything that writes to NUL, which includes parts of git).";
	return text;
}

std::string glaipnir::platform::windows::detail::exposure_warning(const std::vector<std::filesystem::path>& exposed)
{
	std::string text = "exposed_folders = \"warn\": the sandboxed program CAN READ these folders in your profile:";
	for (const auto& path : exposed)
	{
		text += " " + core::to_display_string(path);
	}
	return text;
}

std::string glaipnir::platform::windows::detail::exposure_denial(const std::vector<std::filesystem::path>& exposed)
{
	return "exposed_folders = \"deny\": blocking " + std::to_string(exposed.size()) +
		" folder(s) in your profile for this session; the first run after a change can be slow for big folders";
}

std::string glaipnir::platform::windows::detail::restricted_token_limits()
{
	return "restricted_token cannot protect: files outside your profile that every user may read (often data "
		"drives such as D:\\), and the network (the program has full internet access)";
}
