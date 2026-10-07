#ifdef _WIN32

#include "support/sandbox_fixture.hpp"

#include "glaipnir/core/c_sandbox.hpp"

glaipnir::test::sandbox_fixture_t::sandbox_fixture_t() : host(policy::host_context_t::detect(temp.path() / "state")) {}

glaipnir::test::sandbox_fixture_t::~sandbox_fixture_t() {
    if (auto ids = core::c_session::list(state_root())) {
        for (const auto& id : *ids) {
            (void)core::c_session::destroy(state_root(), id);
        }
    }
}

std::filesystem::path glaipnir::test::sandbox_fixture_t::state_root() const {
    return temp.path() / "state";
}

glaipnir::core::result_t<glaipnir::policy::c_policy>
glaipnir::test::sandbox_fixture_t::policy_from(const std::string& text) const {
    return policy::c_policy::parse(text, host);
}

glaipnir::core::result_t<glaipnir::core::c_session> glaipnir::test::sandbox_fixture_t::session(const std::string& id) const {
    return core::c_session::open({id, state_root(), false}, core::open_mode::open_or_create);
}

std::filesystem::path glaipnir::test::sandbox_fixture_t::workspace(const std::string& id) const {
    return core::c_session::directory_for(state_root(), id) / "workspace";
}

glaipnir::core::result_t<glaipnir::isolation::sandbox_result_t>
glaipnir::test::sandbox_fixture_t::run(const std::string& id, const std::string& policy_text, const std::string& line) const {
    auto policy = policy_from(policy_text);
    if (!policy) {
        return std::move(policy).error();
    }
    auto opened = session(id);
    if (!opened) {
        return std::move(opened).error();
    }
    auto sandbox = core::c_sandbox::create(std::move(*policy), *opened);
    if (!sandbox) {
        return std::move(sandbox).error();
    }
    return sandbox->run({std::string{cmd_exe}, "/d", "/c", line});
}

std::string glaipnir::test::path_text(const std::filesystem::path& path) {
    return path.string();
}

#endif
