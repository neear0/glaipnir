#include "glaipnir/platform/windows/c_windows_backend.hpp"

#include "win_util.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <fstream>
#include <map>
#include <system_error>
#include <vector>

#include "glaipnir/core/path_util.hpp"
#include "glaipnir/platform/windows/command_line.hpp"
#include "glaipnir/platform/windows/path_acl.hpp"

namespace glaipnir::platform::windows {

using core::error_code;
using core::make_error;
using core::result_t;
using policy::access_mode;

namespace fs = std::filesystem;

namespace {

constexpr std::string_view ledger_file_name = "grants.ledger";
constexpr unsigned timeout_exit_code = 124; // same convention as coreutils timeout(1)
constexpr unsigned terminated_exit_code = 137;

std::string container_moniker(std::string_view session_id) {
    return "glaipnir." + std::string{session_id};
}

// ---- grant ledger ---------------------------------------------------------------------------
// Every DACL change is written down *before* it is made, so a crash between granting and
// revoking still leaves enough information to undo it on the next run or on session delete.

struct ledger_entry_t {
    fs::path path;
    access_mode access = access_mode::read_only;
};

std::vector<ledger_entry_t> read_ledger(const fs::path& file) {
    std::vector<ledger_entry_t> entries;
    std::ifstream input(file, std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
        if (line.size() < 4 || line[2] != '\t') {
            continue;
        }
        entries.push_back({core::from_utf8(std::string_view{line}.substr(3)),
                           line.starts_with("rw") ? access_mode::read_write : access_mode::read_only});
    }
    return entries;
}

result_t<void> write_ledger(const fs::path& file, const std::vector<ledger_entry_t>& entries) {
    const auto scratch = fs::path{file}.concat(".new");
    {
        std::ofstream output(scratch, std::ios::binary | std::ios::trunc);
        for (const auto& entry : entries) {
            const auto path_text = entry.path.u8string();
            output << (entry.access == access_mode::read_write ? "rw" : "ro") << '\t'
                   << std::string{path_text.begin(), path_text.end()} << '\n';
        }
        output.flush();
        if (!output) {
            return make_error(error_code::io_error, "cannot write grant ledger " + core::to_display_string(scratch));
        }
    }
    std::error_code ec;
    fs::rename(scratch, file, ec);
    if (ec) {
        return make_error(error_code::io_error, "cannot replace grant ledger: " + ec.message(), ec.value());
    }
    return core::ok();
}

bool same_path(const fs::path& a, const fs::path& b) {
    return core::is_same_or_inside(a, b) && core::is_same_or_inside(b, a);
}

std::string_view outcome_name(grant_outcome outcome) {
    switch (outcome) {
    case grant_outcome::unchanged: return "unchanged";
    case grant_outcome::granted: return "granted";
    case grant_outcome::already_allowed: return "already_allowed";
    }
    return "unknown";
}

// ---- environment ----------------------------------------------------------------------------

struct case_insensitive_less_t {
    bool operator()(const std::wstring& a, const std::wstring& b) const noexcept {
        return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) ==
               CSTR_LESS_THAN;
    }
};

std::wstring host_variable(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) {
        return {};
    }
    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    value.resize(written);
    return value;
}

// Non-secret variables that Windows itself and common runtimes break without
// (e.g. Winsock and CryptoAPI need SystemRoot). Nothing user-specific is in this list.
constexpr std::array<const wchar_t*, 18> essential_variables{
    L"SystemRoot", L"windir", L"SystemDrive", L"ComSpec", L"PATHEXT", L"OS",
    L"NUMBER_OF_PROCESSORS", L"PROCESSOR_ARCHITECTURE", L"PROCESSOR_IDENTIFIER", L"PROCESSOR_LEVEL",
    L"PROCESSOR_REVISION", L"ProgramData", L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432",
    L"CommonProgramFiles", L"CommonProgramFiles(x86)", L"CommonProgramW6432",
};

// ---- process attributes ---------------------------------------------------------------------

class c_attribute_list {
public:
    static result_t<c_attribute_list> create(DWORD count) {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, count, 0, &size);
        c_attribute_list list;
        list.storage_.resize(size);
        auto* raw = list.get();
        if (!InitializeProcThreadAttributeList(raw, count, 0, &size)) {
            return last_error("cannot initialize process attributes");
        }
        list.initialized_ = true;
        return list;
    }

    c_attribute_list(c_attribute_list&& other) noexcept
        : storage_(std::move(other.storage_)), initialized_(std::exchange(other.initialized_, false)) {}
    c_attribute_list& operator=(c_attribute_list&&) = delete;
    ~c_attribute_list() {
        if (initialized_) {
            DeleteProcThreadAttributeList(get());
        }
    }

    LPPROC_THREAD_ATTRIBUTE_LIST get() noexcept {
        return reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
    }

    result_t<void> set(DWORD_PTR attribute, void* value, SIZE_T size, std::string_view what) {
        if (!UpdateProcThreadAttribute(get(), 0, attribute, value, size, nullptr, nullptr)) {
            return last_error("cannot set process attribute " + std::string{what});
        }
        return core::ok();
    }

private:
    c_attribute_list() = default;

    std::vector<std::uint8_t> storage_;
    bool initialized_ = false;
};

struct well_known_sid_t {
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> bytes{};
};

} // namespace

c_windows_backend::c_windows_backend(policy::policy_t policy, std::string session_id, c_app_container container,
                                     fs::path workspace, fs::path container_folder)
    : policy_(std::move(policy)), session_id_(std::move(session_id)), container_(std::move(container)),
      workspace_(std::move(workspace)), container_folder_(std::move(container_folder)) {}

result_t<c_windows_backend> c_windows_backend::prepare(const policy::c_policy& policy, std::string_view session_id,
                                                       const fs::path& session_dir, const fs::path& workspace,
                                                       core::c_audit_log& audit) {
    const auto& data = policy.data();
    using policy::isolation_backend;
    if (data.backend == isolation_backend::windows_sandbox) {
        return make_error(error_code::not_supported, "the windows_sandbox backend is not implemented yet; use app_container");
    }
    if (data.backend == isolation_backend::process || data.backend == isolation_backend::firecracker) {
        return make_error(error_code::not_supported,
                          "backend '" + std::string{policy::to_string(data.backend)} + "' is Linux-only");
    }
    if (data.network == policy::network_mode::proxy) {
        // Refuse rather than silently degrade: a policy that asks for filtered egress must not
        // get either no network (surprising) or open network (unsafe).
        return make_error(error_code::not_supported,
                          "network.mode = \"proxy\" is not available on Windows yet; use \"none\" or \"unrestricted\"");
    }

    auto container = c_app_container::create_or_open(container_moniker(session_id));
    if (!container) {
        return std::move(container).error();
    }
    auto folder = container->folder();
    if (!folder) {
        return std::move(folder).error();
    }
    std::error_code ec;
    for (const auto* sub : {L"home/AppData/Roaming", L"home/AppData/Local", L"tmp"}) {
        fs::create_directories(*folder / sub, ec);
        if (ec) {
            return make_error(error_code::io_error, "cannot create sandbox profile directories: " + ec.message(), ec.value());
        }
    }

    std::vector<ledger_entry_t> desired{{workspace, access_mode::read_write}};
    for (const auto& rule : data.paths) {
        desired.push_back({rule.path, rule.access});
    }

    const auto ledger = session_dir / ledger_file_name;
    auto recorded = read_ledger(ledger);
    for (const auto& old : recorded) {
        const bool still_wanted =
            std::any_of(desired.begin(), desired.end(), [&](const auto& want) { return same_path(want.path, old.path); });
        if (!still_wanted) {
            auto revoked = revoke_path_access(old.path, container->sid());
            if (!revoked) {
                return std::move(revoked).error();
            }
            (void)audit.record("grant.revoke", core::to_display_string(old.path));
        }
    }

    auto union_entries = desired;
    for (const auto& old : recorded) {
        if (std::none_of(union_entries.begin(), union_entries.end(), [&](const auto& e) { return same_path(e.path, old.path); })) {
            union_entries.push_back(old);
        }
    }
    auto written = write_ledger(ledger, union_entries);
    if (!written) {
        return std::move(written).error();
    }

    for (const auto& want : desired) {
        auto outcome = grant_path_access(want.path, container->sid(), want.access, data.less_privileged);
        if (!outcome) {
            (void)audit.record("grant.denied", core::to_display_string(want.path) + ": " + outcome.error().message);
            return std::move(outcome).error();
        }
        (void)audit.record("grant.path", std::format("{} {} ({})", want.access == access_mode::read_write ? "rw" : "ro",
                                                     core::to_display_string(want.path), outcome_name(*outcome)));
    }
    written = write_ledger(ledger, desired);
    if (!written) {
        return std::move(written).error();
    }

    (void)audit.record("sandbox.prepare", std::format("backend=app_container sid={} lpac={} network={}",
                                                      container->sid_string(), data.less_privileged,
                                                      policy::to_string(data.network)));
    return c_windows_backend{data, std::string{session_id}, std::move(*container), workspace, std::move(*folder)};
}

result_t<std::wstring> c_windows_backend::build_environment(const isolation::launch_spec_t& spec) const {
    std::map<std::wstring, std::wstring, case_insensitive_less_t> variables;
    for (const auto* name : essential_variables) {
        auto value = host_variable(name);
        if (!value.empty()) {
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

    for (const auto& [name, value] : spec.environment) {
        variables[to_wide(name)] = to_wide(value);
    }
    variables[L"GLAIPNIR_SESSION"] = to_wide(session_id_);
    variables[L"GLAIPNIR_WORKSPACE"] = workspace_.native();

    std::wstring block;
    for (const auto& [name, value] : variables) {
        if (value.find(L'\0') != std::wstring::npos) {
            return make_error(error_code::invalid_argument, "environment value for " + from_wide(name) + " contains NUL");
        }
        block += name;
        block += L'=';
        block += value;
        block += L'\0';
    }
    block += L'\0';
    return block;
}

result_t<void> c_windows_backend::start(const isolation::launch_spec_t& spec) {
    if (process_.valid()) {
        return make_error(error_code::busy, "sandbox already started");
    }
    if (spec.argv.empty()) {
        return make_error(error_code::invalid_argument, "no command given");
    }

    // Resolve with the PATH the sandbox will see when the policy passes one, else the host's:
    // the command line was typed on the host, so host lookup is what the user expects.
    std::wstring search_path = host_variable(L"PATH");
    for (const auto& [name, value] : spec.environment) {
        if (CompareStringOrdinal(to_wide(name).c_str(), -1, L"PATH", -1, TRUE) == CSTR_EQUAL) {
            search_path = to_wide(value);
        }
    }
    auto executable = resolve_executable(to_wide(spec.argv.front()), search_path, host_variable(L"PATHEXT"));
    if (!executable) {
        return std::move(executable).error();
    }
    auto extension = executable->extension().native();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
    if (extension == L".bat" || extension == L".cmd") {
        // cmd.exe re-parses batch arguments with its own rules, so CRT-style quoting cannot
        // guarantee arguments arrive intact (the "BatBadBut" class of injection).
        return make_error(error_code::invalid_argument,
                          "refusing to launch batch file " + core::to_display_string(*executable) +
                              " directly; run it explicitly via `cmd /c` if you accept cmd's argument parsing");
    }

    std::vector<std::wstring> wide_argv{executable->native()};
    for (std::size_t i = 1; i < spec.argv.size(); ++i) {
        wide_argv.push_back(to_wide(spec.argv[i]));
    }
    auto command_line = build_command_line(wide_argv);
    if (!command_line) {
        return std::move(command_line).error();
    }
    auto environment = build_environment(spec);
    if (!environment) {
        return std::move(environment).error();
    }

    auto job = c_job_object::create(session_id_, policy_.limits, policy_.capabilities);
    if (!job) {
        return std::move(job).error();
    }

    // Capabilities: only what the network policy implies. internetClient reaches the internet
    // but not private/LAN ranges, which keeps cloud metadata and intranet services out of reach.
    std::vector<well_known_sid_t> capability_sids;
    std::vector<SID_AND_ATTRIBUTES> capabilities;
    if (policy_.network == policy::network_mode::unrestricted) {
        well_known_sid_t sid;
        DWORD size = static_cast<DWORD>(sid.bytes.size());
        if (!CreateWellKnownSid(WinCapabilityInternetClientSid, nullptr, sid.bytes.data(), &size)) {
            return last_error("cannot build internetClient capability");
        }
        capability_sids.push_back(sid);
    }
    for (auto& sid : capability_sids) {
        capabilities.push_back({sid.bytes.data(), SE_GROUP_ENABLED});
    }
    SECURITY_CAPABILITIES security{};
    security.AppContainerSid = container_.sid();
    security.Capabilities = capabilities.empty() ? nullptr : capabilities.data();
    security.CapabilityCount = static_cast<DWORD>(capabilities.size());

    // Inherit only the three standard handles; anything else glaipnir has open stays out.
    std::vector<HANDLE> inherited;
    for (const DWORD which : {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
        HANDLE handle = GetStdHandle(which);
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
            std::find(inherited.begin(), inherited.end(), handle) != inherited.end()) {
            continue;
        }
        if (SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
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

    const DWORD attribute_count = 3 + (inherited.empty() ? 0 : 1) + (policy_.capabilities.child_processes ? 0 : 1) +
                                  (policy_.less_privileged ? 1 : 0);
    auto attributes = c_attribute_list::create(attribute_count);
    if (!attributes) {
        return std::move(attributes).error();
    }
    std::array<result_t<void>, 6> updates{
        attributes->set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security, sizeof(security), "security capabilities"),
        // JOB_LIST places the process in the job before its first instruction runs; assigning
        // afterwards would leave a window in which it could spawn an unconfined child.
        attributes->set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handle, sizeof(job_handle), "job list"),
        attributes->set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigations, sizeof(mitigations), "mitigation policy"),
        inherited.empty() ? core::ok()
                          : attributes->set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(),
                                            inherited.size() * sizeof(HANDLE), "handle list"),
        policy_.capabilities.child_processes
            ? core::ok()
            : attributes->set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy, sizeof(child_policy), "child process policy"),
        !policy_.less_privileged ? core::ok()
                                 : attributes->set(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &packages_policy,
                                                   sizeof(packages_policy), "LPAC policy"),
    };
    for (auto& update : updates) {
        if (!update) {
            return std::move(update).error();
        }
    }

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes->get();
    if (!inherited.empty()) {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }

    const fs::path working_directory = spec.working_directory.empty() ? workspace_ : spec.working_directory;
    PROCESS_INFORMATION info{};
    if (!CreateProcessW(executable->c_str(), command_line->data(), nullptr, nullptr, inherited.empty() ? FALSE : TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT, environment->data(),
                        working_directory.c_str(), &startup.StartupInfo, &info)) {
        const DWORD code = GetLastError();
        std::string hint;
        if (code == ERROR_ACCESS_DENIED) {
            hint = "; the sandbox cannot read " + core::to_display_string(*executable) +
                   " or its directory. Add the program's install directory to filesystem.read";
        }
        return win32_error("cannot start " + core::to_display_string(*executable) + hint, code);
    }
    CloseHandle(info.hThread);
    process_.reset(info.hProcess);
    job_.emplace(std::move(*job));
    started_at_ = std::chrono::steady_clock::now();
    return core::ok();
}

result_t<isolation::sandbox_result_t> c_windows_backend::wait() {
    if (!process_.valid() || !job_) {
        return make_error(error_code::invalid_argument, "sandbox was not started");
    }
    isolation::sandbox_result_t result;

    const auto wall_limit = std::chrono::seconds{policy_.limits.wall_timeout_seconds};
    bool timed_out = false;
    while (true) {
        DWORD wait_ms = INFINITE;
        if (wall_limit.count() != 0) {
            const auto remaining = wall_limit - (std::chrono::steady_clock::now() - started_at_);
            const auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
            if (remaining_ms <= 0) {
                timed_out = true;
                break;
            }
            // Wait in bounded slices: a DWORD timeout tops out at ~49 days.
            wait_ms = static_cast<DWORD>(std::min<long long>(remaining_ms, 24LL * 3600 * 1000));
        }
        const DWORD status = WaitForSingleObject(process_.get(), wait_ms);
        if (status == WAIT_OBJECT_0) {
            break;
        }
        if (status != WAIT_TIMEOUT) {
            return last_error("waiting for sandboxed process failed");
        }
    }
    if (timed_out) {
        (void)job_->terminate(timeout_exit_code);
        WaitForSingleObject(process_.get(), INFINITE);
        result.reason = isolation::termination_reason::wall_timeout;
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(process_.get(), &exit_code);
    result.exit_code = static_cast<int>(exit_code);
    result.wall_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_at_);

    if (auto usage = job_->usage()) {
        result.cpu_time = usage->user_time + usage->kernel_time;
        result.peak_memory_bytes = usage->peak_memory_bytes;
        const auto cpu_limit = std::chrono::seconds{policy_.limits.cpu_timeout_seconds};
        if (!timed_out && cpu_limit.count() != 0 && usage->user_time >= cpu_limit) {
            result.reason = isolation::termination_reason::cpu_timeout;
        }
    }
    if (terminated_->load()) {
        result.reason = isolation::termination_reason::terminated;
    }
    // The root exited; anything it left running (daemons, watchers) dies with the run.
    (void)job_->terminate(exit_code);
    process_.reset();
    return result;
}

result_t<void> c_windows_backend::pause() const {
    if (!job_) {
        return make_error(error_code::invalid_argument, "sandbox was not started");
    }
    return job_->suspend();
}

result_t<void> c_windows_backend::resume() const {
    if (!job_) {
        return make_error(error_code::invalid_argument, "sandbox was not started");
    }
    return job_->resume();
}

result_t<void> c_windows_backend::terminate() const {
    if (!job_) {
        return make_error(error_code::invalid_argument, "sandbox was not started");
    }
    terminated_->store(true);
    return job_->terminate(terminated_exit_code);
}

result_t<void> c_windows_backend::cleanup(std::string_view session_id, const fs::path& session_dir) {
    const auto ledger = session_dir / ledger_file_name;
    const auto entries = read_ledger(ledger);
    if (!entries.empty()) {
        auto container = c_app_container::create_or_open(container_moniker(session_id));
        if (!container) {
            return std::move(container).error();
        }
        for (const auto& entry : entries) {
            // Paths inside the session directory are about to be deleted; re-ACLing them first
            // would only cost a full tree walk.
            if (core::is_same_or_inside(entry.path, session_dir)) {
                continue;
            }
            auto revoked = revoke_path_access(entry.path, container->sid());
            if (!revoked) {
                return revoked;
            }
        }
    }
    std::error_code ec;
    fs::remove(ledger, ec);
    return c_app_container::remove(container_moniker(session_id));
}

result_t<void> c_windows_backend::pause_running(std::string_view session_id) {
    auto job = c_job_object::open(session_id);
    if (!job) {
        return std::move(job).error();
    }
    return job->suspend();
}

result_t<void> c_windows_backend::resume_running(std::string_view session_id) {
    auto job = c_job_object::open(session_id);
    if (!job) {
        return std::move(job).error();
    }
    return job->resume();
}

result_t<void> c_windows_backend::terminate_running(std::string_view session_id) {
    auto job = c_job_object::open(session_id);
    if (!job) {
        return std::move(job).error();
    }
    return job->terminate(terminated_exit_code);
}

} // namespace glaipnir::platform::windows
