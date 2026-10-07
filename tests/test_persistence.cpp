#include "test_harness.hpp"

#include "glaipnir/core/c_session.hpp"
#include "glaipnir/persistence/c_volume.hpp"
#include "glaipnir/persistence/safe_fs.hpp"

#ifdef _WIN32
#include <cstdlib>
#endif

using namespace glaipnir;
namespace fs = std::filesystem;

glaipnir_test(volume_snapshot_and_rollback) {
    test::c_temp_dir temp;
    auto volume = persistence::c_volume::open(temp.path() / "vol");
    glaipnir_require_ok(volume);
    const auto workspace = volume->workspace();
    fs::create_directories(workspace / "src");
    test::write_file(workspace / "src" / "main.py", "print('v1')");
    test::write_file(workspace / "notes.txt", "first");

    auto snap = volume->snapshot("v1", "digest");
    glaipnir_require_ok(snap);
    glaipnir_check(snap->snapshot.files == 2);

    test::write_file(workspace / "src" / "main.py", "print('v2')");
    test::write_file(workspace / "extra.txt", "new");
    fs::remove(workspace / "notes.txt");

    glaipnir_require(volume->rollback("v1").has_value());
    glaipnir_check(test::read_file(workspace / "src" / "main.py") == "print('v1')");
    glaipnir_check(test::read_file(workspace / "notes.txt") == "first");
    glaipnir_check(!fs::exists(workspace / "extra.txt"));

    glaipnir_check(!volume->snapshot("v1", "").has_value());          // duplicate label
    glaipnir_check(!volume->snapshot("../evil", "").has_value());     // traversal
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
    test::c_temp_dir temp;
    const auto outside = temp.path() / "host-secrets";
    fs::create_directories(outside);
    test::write_file(outside / "id_rsa", "PRIVATE KEY");

    auto volume = persistence::c_volume::open(temp.path() / "vol");
    glaipnir_require_ok(volume);
    test::write_file(volume->workspace() / "ok.txt", "fine");
#ifdef _WIN32
    // Junctions need no privilege, which is exactly why an agent could plant one.
    const auto command = "mklink /J \"" + (volume->workspace() / "link").string() + "\" \"" + outside.string() + "\" >NUL";
    glaipnir_require(std::system(command.c_str()) == 0);
#else
    fs::create_directory_symlink(outside, volume->workspace() / "link");
#endif
    glaipnir_require(fs::exists(volume->workspace() / "link" / "id_rsa"));

    auto snap = volume->snapshot("s", "");
    glaipnir_require_ok(snap);
    glaipnir_check(snap->snapshot.files == 1);
    glaipnir_check(snap->snapshot.skipped_links == 1);
    glaipnir_check(!fs::exists(volume->root() / "snapshots" / "s" / "data" / "link"));

    // Removing the workspace must delete the link, not the files it points at.
    glaipnir_require(persistence::remove_tree(volume->workspace()).has_value());
    glaipnir_check(fs::exists(outside / "id_rsa"));
}

glaipnir_test(remove_tree_handles_read_only_files) {
    test::c_temp_dir temp;
    const auto dir = temp.path() / "repo" / ".git" / "objects";
    fs::create_directories(dir);
    test::write_file(dir / "pack", "data");
    fs::permissions(dir / "pack", fs::perms::owner_write, fs::perm_options::remove);
    glaipnir_check(persistence::remove_tree(temp.path() / "repo").has_value());
    glaipnir_check(!fs::exists(temp.path() / "repo"));
}

glaipnir_test(session_lifecycle_lock_and_fork) {
    test::c_temp_dir temp;
    persistence::session_config_t config{"alpha", temp.path(), false};
    {
        auto session = core::c_session::open(config, core::open_mode::create);
        glaipnir_require_ok(session);
        // A second opener must be refused while the first holds the lock.
        auto second = core::c_session::open(config, core::open_mode::open_existing);
        glaipnir_check(!second.has_value() && second.error().code == core::error_code::busy);

        test::write_file(session->volume().workspace() / "state.json", "{\"step\": 3}");
        glaipnir_require(session->snapshot("checkpoint-1").has_value());
        auto child = session->fork_session("beta");
        glaipnir_require_ok(child);
        glaipnir_check(test::read_file(child->volume().workspace() / "state.json") == "{\"step\": 3}");
        auto child_snaps = child->snapshots();
        glaipnir_check(child_snaps && child_snaps->size() == 1);
    }
    glaipnir_check(!core::c_session::open(config, core::open_mode::create).has_value()); // exists
    auto ids = core::c_session::list(temp.path());
    glaipnir_require_ok(ids);
    glaipnir_check((*ids == std::vector<std::string>{"alpha", "beta"}));

    glaipnir_require(core::c_session::destroy(temp.path(), "beta").has_value());
    glaipnir_check(!fs::exists(core::c_session::directory_for(temp.path(), "beta")));
    // The audit trail outlives the session and still verifies.
    auto verified = core::c_audit_log::verify(core::c_session::audit_path_for(temp.path(), "beta"));
    glaipnir_check(verified.has_value());
    glaipnir_check(core::c_audit_log::verify(core::c_session::audit_path_for(temp.path(), "alpha")).has_value());
    glaipnir_require(core::c_session::destroy(temp.path(), "alpha").has_value());
}
