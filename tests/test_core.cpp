#include "test_harness.hpp"

#include <fstream>

#include "glaipnir/core/c_audit_log.hpp"
#include "glaipnir/core/c_sha256.hpp"
#include "glaipnir/core/path_util.hpp"
#include "glaipnir/core/validation.hpp"

using namespace glaipnir;
using core::c_sha256;

glaipnir_test(sha256_known_vectors) {
    glaipnir_check(c_sha256::hex_digest("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    glaipnir_check(c_sha256::hex_digest("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    glaipnir_check(c_sha256::hex_digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
                   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    // One million 'a' fed in uneven chunks exercises the buffering path.
    c_sha256 hasher;
    const std::string chunk(997, 'a');
    std::size_t fed = 0;
    while (fed < 1'000'000) {
        const auto take = std::min<std::size_t>(chunk.size(), 1'000'000 - fed);
        hasher.update(std::string_view{chunk}.substr(0, take));
        fed += take;
    }
    glaipnir_check(c_sha256::to_hex(hasher.finish()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

glaipnir_test(identifier_validation) {
    glaipnir_check(core::validate_identifier("my-agent_01", "id").has_value());
    glaipnir_check(core::validate_identifier("0abc", "id").has_value());
    glaipnir_check(!core::validate_identifier("", "id").has_value());
    glaipnir_check(!core::validate_identifier("-lead", "id").has_value());
    glaipnir_check(!core::validate_identifier("Upper", "id").has_value());
    glaipnir_check(!core::validate_identifier("../escape", "id").has_value());
    glaipnir_check(!core::validate_identifier("a/b", "id").has_value());
    glaipnir_check(!core::validate_identifier("a.b", "id").has_value());
    glaipnir_check(!core::validate_identifier("nul", "id").has_value());
    glaipnir_check(!core::validate_identifier("com1", "id").has_value());
    glaipnir_check(core::validate_identifier("com10", "id").has_value());
    glaipnir_check(!core::validate_identifier(std::string(49, 'a'), "id").has_value());
}

glaipnir_test(path_containment) {
    using core::is_same_or_inside;
#ifdef _WIN32
    glaipnir_check(is_same_or_inside("C:\\Users\\me\\code", "C:\\Users\\me"));
    glaipnir_check(is_same_or_inside("c:/users/ME/code", "C:\\Users\\me"));
    glaipnir_check(is_same_or_inside("C:\\Users\\me", "C:\\Users\\me\\"));
    glaipnir_check(!is_same_or_inside("C:\\Users\\meow", "C:\\Users\\me"));
    glaipnir_check(!is_same_or_inside("C:\\Users", "C:\\Users\\me"));
    glaipnir_check(!is_same_or_inside("D:\\Users\\me", "C:\\Users\\me"));
    glaipnir_check(is_same_or_inside("C:\\Users\\me\\a\\..\\b", "C:\\Users\\me"));
#else
    glaipnir_check(is_same_or_inside("/home/me/code", "/home/me"));
    glaipnir_check(!is_same_or_inside("/home/meow", "/home/me"));
#endif
}

glaipnir_test(audit_log_chain_and_tamper_detection) {
    test::c_temp_dir temp;
    const auto path = temp.path() / "audit.log";
    {
        auto log = core::c_audit_log::open(path);
        glaipnir_require_ok(log);
        glaipnir_require(log->record("run.start", "first \"quoted\" \\ detail\n").has_value());
        glaipnir_require(log->record("run.end", "exit=0").has_value());
    }
    {
        // Reopening must continue the chain, not restart it.
        auto log = core::c_audit_log::open(path);
        glaipnir_require_ok(log);
        glaipnir_require(log->record("run.start", "second").has_value());
    }
    auto verified = core::c_audit_log::verify(path);
    glaipnir_require_ok(verified);
    glaipnir_check(*verified == 3);

    // Edit one character of the middle record.
    auto content = test::read_file(path);
    const auto pos = content.find("exit=0");
    glaipnir_require(pos != std::string::npos);
    content[pos + 5] = '1';
    test::write_file(path, content);
    auto tampered = core::c_audit_log::verify(path);
    glaipnir_check(!tampered.has_value());
    glaipnir_check(!tampered.has_value() && tampered.error().code == core::error_code::integrity_error);

    // Deleting a line breaks the chain too.
    auto lines = test::read_file(path);
    test::write_file(path, lines.substr(lines.find('\n') + 1));
    glaipnir_check(!core::c_audit_log::verify(path).has_value());
}

glaipnir_test(json_escape_controls) {
    glaipnir_check(core::json_escape("a\"b\\c\n\x01") == "a\\\"b\\\\c\\n\\u0001");
}
