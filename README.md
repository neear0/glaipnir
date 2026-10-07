# glAIpnir

[![ci](https://github.com/neear0/glaipnir/actions/workflows/ci.yml/badge.svg)](https://github.com/neear0/glaipnir/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A lightweight, deny-by-default sandbox for running AI agents, written in C++20.

An agent launched through glaipnir never inherits your account's full reach. It gets a durable
workspace, whatever paths and capabilities the policy explicitly grants, and nothing else: no home
directory, no credential stores, no inherited environment variables, no network unless asked for.
The workspace survives across runs and can be snapshotted, rolled back and forked, so an agent never
loses its context.

```
glaipnir run --policy policies/offline_coding_agent.toml --session my-agent -- python agent.py
```

## Status

Version 0.1, Windows-first. The Windows AppContainer backend is implemented and tested; other
backends are designed for but not written yet.

| Area | Windows | Linux | macOS |
|---|---|---|---|
| Policy language, validation, audit log | done | done (portable code) | done (portable code) |
| Process isolation | **AppContainer + Job Object** | Landlock + seccomp + namespaces: planned | Seatbelt: planned |
| Filesystem allow-list | **per-session DACL grants** | Landlock: planned | Seatbelt: planned |
| Network `none` / `unrestricted` | **done** | planned | planned |
| Network `proxy` (domain allow-list + credential injection) | planned | planned | planned |
| Resource limits (memory, CPU, pids, wall/CPU timeouts) | **done** | cgroup v2: planned | planned |
| Workspace snapshots / rollback / fork | **done** | done (portable code, untested) | done (portable code, untested) |
| Pause / resume | **done** (thread suspension) | planned (cgroup freezer) | planned |
| Process checkpoints (CRIU) | n/a | planned | n/a |
| MicroVM backend | Windows Sandbox / Hyper-V: planned | Firecracker: planned | n/a |

Policies that ask for something a backend cannot enforce are **refused**, never silently weakened.

## Building

Requires Visual Studio 2022 (or the Build Tools) with the C++ workload and a Windows 10 SDK.

```
msbuild glaipnir.sln -p:Configuration=Release -p:Platform=x64
bin\x64\Release\glaipnir_tests.exe
```

The result is a single statically linked `bin\x64\Release\glaipnir.exe` (no VC++ redistributable).
No third-party dependencies.

On Linux the portable parts (policy, audit log, persistence) build and test with a plain Makefile;
there is no Linux isolation backend or CLI yet.

```
make test                      # g++ by default; CXX=clang++ also works
make test SANITIZE=1           # with AddressSanitizer + UBSan
make fuzz FUZZ_CXX=clang++     # libFuzzer targets for the TOML and policy parsers
```

CI (GitHub Actions) runs the Windows build and tests in Debug and Release, the Linux tests under
sanitizers with GCC and Clang, and a short fuzzing pass on every push.

## Usage

```
glaipnir run [--policy FILE] [--session ID] [--cwd DIR] -- COMMAND [ARGS...]
glaipnir policy check FILE
glaipnir session list
glaipnir session create|delete|pause|resume|kill ID
glaipnir session fork SOURCE_ID NEW_ID
glaipnir snapshot list SESSION
glaipnir snapshot create|rollback|delete SESSION LABEL
glaipnir audit verify SESSION
```

- Without `--policy`, the run gets the deny-all policy.
- Without `--session`, the run uses a throwaway session that is deleted afterwards (its audit log is kept).
- Exit code is the sandboxed command's; `124` on timeout, `125` when glaipnir itself failed.
- State lives in `%LOCALAPPDATA%\glaipnir` (override with `--state-dir` or `GLAIPNIR_STATE_DIR`).

Example: checkpoint before letting an agent loose, roll back if it goes wrong.

```
glaipnir snapshot create my-agent before-refactor
glaipnir run --policy agent.toml --session my-agent -- python agent.py
glaipnir snapshot rollback my-agent before-refactor
```

## Policies

Policies are TOML; see [docs/policy.md](docs/policy.md) for the full reference and
[policies/](policies/) for examples. The parser accepts a strict subset of TOML and rejects
unknown keys, so a typo is an error rather than a silently ignored rule.

```toml
[sandbox]
name = "offline-coding-agent"

[filesystem]
write = ["${cwd}"]          # the project you launched from

[network]
mode = "none"

[env]
pass = ["PATH"]             # nothing else from the host environment

[limits]
memory_mb = 4096
wall_timeout_s = 7200

[capabilities]
child_processes = true      # git, node, python, ...
```

Validation refuses, among other things: the home directory or any ancestor of it, known credential
locations (`~/.ssh`, `~/.aws`, browser profiles, Windows credential vaults, ...), the glaipnir state
directory, drive roots, and environment variables whose names look like secrets (`*TOKEN*`,
`*_KEY`, ...). Credentials are meant to be injected by the network proxy, never handed to the agent.

## Security model

- **Deny by default.** Every permission is an explicit allow-list entry.
- **Per-session identity.** Each session runs under its own AppContainer SID, so sessions cannot read
  each other's workspaces even though they belong to the same user.
- **Rules are re-applied on every run.** Snapshots and forks carry files, never permissions; grants
  are recomputed from the current policy each time, and grants dropped from a policy are revoked.
- **Host-side file operations never follow links.** Snapshot, rollback, fork and delete skip
  symlinks and junctions, so an agent cannot plant a link that makes glaipnir copy host secrets into
  its workspace.
- **Audit trail.** Every policy decision, grant and execution is appended to a SHA-256 hash-chained
  log (`glaipnir audit verify`). The chain detects edits, deletions and reordering; it cannot stop
  someone with write access to the log from truncating its tail.

Platform-specific details and known limitations are in [docs/windows.md](docs/windows.md).

## Code layout

```
include/glaipnir/<area>/      public headers (core, policy, persistence, isolation, platform)
src/<area>/                   implementations; src/platform/windows is the Windows backend
src/<area>/detail/            private helpers, namespace glaipnir::<area>::detail
cli/  cli/detail/             the glaipnir command-line tool
tests/<area>/                 tests per area; tests/support/ holds the harness and fixtures
fuzz/                         libFuzzer targets
policies/                     example policies
msvc/                         Visual Studio projects (shared settings in glaipnir.props)
```

Coding rules (enforced by `tests/conventions/test_conventions.cpp`):

- Classes start with `c_`, structs end with `_t`, everything else is `snake_case`.
- `.cpp` files never use the `namespace` keyword: no namespace blocks, no anonymous namespaces,
  no aliases, no `using namespace`. Every definition is written with its qualified name, e.g.
  `void glaipnir::core::c_sha256::update(...)`. File-private helpers go in a named `detail`
  namespace declared in a header under the area's `detail/` folder.
- `.cpp` file names are unique within a project (MSBuild puts all object files in one folder).

## Roadmap

1. Network proxy with domain allow-list and credential injection (needs an AppContainer loopback
   exemption or WFP rules on Windows).
2. Restricted-token Windows backend for tools that break under AppContainer (see docs/windows.md).
3. Linux backend: Landlock, seccomp, namespaces, cgroup v2; CI on GitHub Actions.
4. Windows Sandbox (`.wsb`) backend; CRIU and Firecracker checkpoints; macOS Seatbelt.

## License

Apache License 2.0, see [LICENSE](LICENSE).
