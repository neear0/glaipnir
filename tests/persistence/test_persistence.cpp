#include "support/test_harness.hpp"

#include "glaipnir/core/c_session.hpp"
#include "glaipnir/persistence/c_volume.hpp"
#include "glaipnir/persistence/safe_fs.hpp"

#ifdef _WIN32
#include <cstdlib>
#endif

using glaipnir::core::c_audit_log;
using glaipnir::core::c_session;
using glaipnir::core::open_mode;
using glaipnir::persistence::c_volume;
using glaipnir::test::c_temp_dir;
using glaipnir::test::read_file;
using glaipnir::test::write_file;

glaipnir_test(volume_snapshot_and_rollback) {
    c_temp_dir temp;
    auto volume = c_volume::open(temp.path() / "vol");
    glaipnir_require_ok(volume);
    const auto workspace = volume->workspace();
    std::filesystem::create_directories(workspace / "src");
    write_file(workspace / "src" / "main.py", "print('v1')");
    write_file(workspace / "notes.txt", "first");

    auto snap = volume->snapshot("v1", "digest");
    glaipnir_require_ok(snap);
    glaipnir_check(snap->snapshot.files == 2);

    write_file(workspace / "src" / "main.py", "print('v2')");
    write_file(workspace / "extra.txt", "new");
    std::filesystem::remove(workspace / "notes.txt");

    glaipnir_require(volume->rollback("v1").has_value());
    glaipnir_check(read_file(workspace / "src" / "main.py") == "print('v1')");
    glaipnir_check(read_file(workspace / "notes.txt") == "first");
    glaipnir_check(!std::filesystem::exists(workspace / "extra.txt"));

    glaipnir_check(!volume->snapshot("v1", "").has_value());
    glaipnir_check(!volume->snapshot("../evil", "").has_value());
    glaipnir_check(!volume->rollback("missing").has_value());

    auto list = volume->list_snapshots();
    glaipnir_require_ok(list);
    glaipnir_require(list->size() == 1);
    glaipnir_check((*list)[0].snapshot.label == "v1" && (*list)[0].policy_digest == "digest");

    glaipnir_require(volume->remove_snapshot("v1").has_value());
    list = volume->list_snapshots();
    glaipnir_check(list && list->empty());
}

glaipnir_test(snapshot_never_follows_links) {
    c_temp_dir temp;
    const auto outside = temp.path() / "host-secrets";
    std::filesystem::create_directories(outside);
    write_file(outside / "id_rsa", "PRIVATE KEY");

    auto volume = c_volume::open(temp.path() / "vol");
    glaipnir_require_ok(volume);
    write_file(volume->workspace() / "ok.txt", "fine");
#ifdef _WIN32
    const auto command = "mklink /J \"" + (volume->workspace() / "link").string() + "\" \"" + outside.string() + "\" >NUL";
    glaipnir_require(std::system(command.c_str()) == 0);
#else
    std::filesystem::create_directory_symlink(outside, volume->workspace() / "link");
#endif
    glaipnir_require(std::filesystem::exists(volume->workspace() / "link" / "id_rsa"));

    auto snap = volume->snapshot("s", "");
    glaipnir_require_ok(snap);
    glaipnir_check(snap->snapshot.files == 1);
    glaipnir_check(snap->snapshot.skipped_links == 1);
    glaipnir_check(!std::filesystem::exists(volume->root() / "snapshots" / "s" / "data" / "link"));

    glaipnir_require(glaipnir::persistence::remove_tree(volume->workspace()).has_value());
    glaipnir_check(std::filesystem::exists(outside / "id_rsa"));
}

glaipnir_test(remove_tree_handles_read_only_files) {
    c_temp_dir temp;
    const auto dir = temp.path() / "repo" / ".git" / "objects";
    std::filesystem::create_directories(dir);
    write_file(dir / "pack", "data");
    std::filesystem::permissions(dir / "pack", std::filesystem::perms::owner_write, std::filesystem::perm_options::remove);
    glaipnir_check(glaipnir::persistence::remove_tree(temp.path() / "repo").has_value());
    glaipnir_check(!std::filesystem::exists(temp.path() / "repo"));
}

glaipnir_test(session_lifecycle_lock_and_fork) {
    c_temp_dir temp;
    glaipnir::persistence::session_config_t config{"alpha", temp.path(), false};
    {
        auto session = c_session::open(config, open_mode::create);
        glaipnir_require_ok(session);
        auto second = c_session::open(config, open_mode::open_existing);
        glaipnir_check(!second.has_value() && second.error().code == glaipnir::core::error_code::busy);

        write_file(session->volume().workspace() / "state.json", "{\"step\": 3}");
        glaipnir_require(session->snapshot("checkpoint-1").has_value());
        auto child = session->fork_session("beta");
        glaipnir_require_ok(child);
        glaipnir_check(read_file(child->volume().workspace() / "state.json") == "{\"step\": 3}");
        auto child_snaps = child->snapshots();
        glaipnir_check(child_snaps && child_snaps->size() == 1);
    }
    glaipnir_check(!c_session::open(config, open_mode::create).has_value());
    auto ids = c_session::list(temp.path());
    glaipnir_require_ok(ids);
    glaipnir_check((*ids == std::vector<std::string>{"alpha", "beta"}));

    glaipnir_require(c_session::destroy(temp.path(), "beta").has_value());
    glaipnir_check(!std::filesystem::exists(c_session::directory_for(temp.path(), "beta")));
    glaipnir_check(c_audit_log::verify(c_session::audit_path_for(temp.path(), "beta")).has_value());
    glaipnir_check(c_audit_log::verify(c_session::audit_path_for(temp.path(), "alpha")).has_value());
    glaipnir_require(c_session::destroy(temp.path(), "alpha").has_value());
}
