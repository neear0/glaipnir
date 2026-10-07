# Windows backends

Both backends run as a normal user on every Windows 10/11 edition, Home included. Neither pretends
to be Landlock or seccomp; each maps the policy onto native primitives. For a plain-language
comparison see [backends.md](backends.md).

## Shared mechanics

| policy | mechanism |
|---|---|
| session identity | a key `<id>.<hash of the session directory>`, so equally named sessions in different state directories never share a profile, SID or Job Object |
| limits | Job Object: memory, active processes, CPU rate cap, CPU time, kill-on-close, no breakaway |
| UI | Job Object UI restrictions: other windows' handles, clipboard, global atoms, desktops, system settings |
| process | mitigation policies (no remote/UNC images, no extension points, heap terminate, system fonts only), optional child-process block, only stdin/stdout/stderr inherited |
| environment | nothing inherited; `HOME`, `TEMP`, `APPDATA`… point into the session's private profile folder |

The process enters its Job Object at creation (`PROC_THREAD_ATTRIBUTE_JOB_LIST`), so there is no
window in which it could spawn an unconfined child. All descendants share the token and the job.

## `app_container`

| policy | mechanism |
|---|---|
| identity | per-session AppContainer profile (optionally LPAC), Low integrity |
| filesystem | DACL grants for the session's package SID on the workspace and policy paths |
| network `none` | no capabilities: no sockets to anything |
| network `unrestricted` | `internetClient` capability only. By Windows' design this excludes private/LAN ranges (that needs `privateNetworkClientServer`, which is never granted); internet access is tested, LAN blocking is not yet covered by a test |

## `restricted_token`

| policy | mechanism |
|---|---|
| identity | restricted copy of the caller's token: all privileges except bypass-traverse removed, Administrators deny-only, Low integrity, default DACL limited to user / SYSTEM / session SID |
| access checks | every access must also pass for one of the restricting SIDs: a per-session SID `S-1-9-…` (derived from the session key), Everyone, Users, RESTRICTED and the logon session. Your own user SID is not among them, so profile folders stay closed |
| filesystem | DACL grants for the session SID; writable paths (workspace, private profile folder, `write` rules) additionally get a Low integrity label, which is what blocks writes to places every user may write, such as `C:\ProgramData` |
| exposed profile folders | before each run, folders up to three levels below home that explicitly grant read to Users / Everyone / RESTRICTED are reported; `sandbox.exposed_folders` decides between refusing, warning and adding a session-specific deny ACE |
| network | not restricted; `network.mode = "none"` is refused for this backend |

Windows rejects AppContainer and capability SIDs (`S-1-15-…`) as restricting SIDs, which is why
the session SID lives under the resource-manager authority `S-1-9`, and why the restricting set
must contain Users (system DLLs grant read only to Users and the package groups).

## Grants and the ledger

Filesystem changes are ACEs and labels on host paths, so they outlive the process. glaipnir writes
every change to `sessions/<id>/grants.ledger` *before* applying it, as `<kind> <sid> <path>` with
kinds `ro`, `rw`, `tr` (traverse), `dn` (deny) and `lw` (Low label). On the next run, entries no
longer wanted are reverted; on `session delete` (and after ephemeral runs) all of them are. Grants
use `SET_ACCESS`, so changing a rule from `write` to `read` really removes write access, and they
never include `WRITE_DAC`/`WRITE_OWNER`. Labels are only removed if glaipnir added them.

- **Traverse grants.** Folders above the workspace and policy paths get a non-inheritable
  "read attributes / traverse" ACE, so tools that stat every parent directory (git) work. They are
  only added to folders you own, never to drive roots, and they are written without re-walking the
  folder's children.
- **Read rules on locations you cannot change** (for example under `C:/Program Files`) are accepted
  when a baseline group already allows them (ALL APPLICATION PACKAGES for `app_container`, Users for
  `restricted_token`); otherwise the run is refused.
- **Inheritable grants and denies on big trees are slow the first time**, because Windows rewrites
  every child's ACL. Later runs detect an identical entry and skip the rewrite.

## Known limitations

`app_container`:

- **Baseline readable locations.** Every AppContainer can read anything that grants
  *ALL APPLICATION PACKAGES*: most of `C:/Windows` and `C:/Program Files`. Nothing in your
  profile grants it. Set `less_privileged = true` (LPAC) to remove this baseline.
- **Drive roots are not accessible.** `dir C:\` fails, and so does cmd.exe when told to start a
  program by absolute path. Pass `PATH` and start programs by name.
- **`NUL` cannot be opened.** The null device does not grant AppContainers access, so
  `> NUL` redirections and tools that write to it (including some git operations) fail.

`restricted_token`:

- **Reads anything readable by Users**, which usually includes data drives such as `D:\`.
  Exposed folders outside the profile, or deeper than three levels inside it, are not checked.
- **Network is always on.**

Both:

- **No filtered network yet.** AppContainers cannot connect to loopback without an
  administrator-installed exemption, and blocking a restricted token's egress needs WFP rules, which
  also need an administrator. Until that exists, `network.mode = "proxy"` is refused.
- **Batch files are refused.** `cmd.exe` re-parses arguments to `.bat`/`.cmd` with its own
  rules, so safe quoting is impossible. Run `cmd /c script.cmd` explicitly if you accept that.
- **Pause** suspends every thread in the job; a thread the agent had itself suspended will be
  resumed by `resume`.

## Not implemented yet

- `windows_sandbox` backend (Hyper-V; not available on Home editions anyway).
- WFP rules binding the sandbox to the proxy port.
- Encryption at rest for snapshots (EFS is unavailable on Home editions).
