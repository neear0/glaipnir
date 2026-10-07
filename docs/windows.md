# Windows backend

The `app_container` backend runs as a normal user on every Windows 10/11 edition, Home included.
It does not pretend to be Landlock or seccomp; it maps the policy onto native primitives.

| policy | mechanism |
|---|---|
| identity | per-session AppContainer profile `glaipnir.<session>` (optionally LPAC), Low integrity token |
| filesystem | explicit DACL grants for the session's package SID on the workspace and policy paths |
| network `none` | no capabilities: no sockets to anything |
| network `unrestricted` | `internetClient` capability only. By Windows' design this excludes private/LAN ranges (that needs `privateNetworkClientServer`, which is never granted); internet access is tested, LAN blocking is not yet covered by a test |
| limits | Job Object: memory, active processes, CPU rate cap, CPU time, kill-on-close, no breakaway |
| UI | Job Object UI restrictions: other windows' handles, clipboard, global atoms, desktops, system settings |
| process | mitigation policies (no remote/UNC images, no extension points, heap terminate, system fonts only), optional child-process block, only stdin/stdout/stderr inherited |

The process enters its Job Object at creation (`PROC_THREAD_ATTRIBUTE_JOB_LIST`), so there is no
window in which it could spawn an unconfined child. All descendants share the token and the job.

## Grants and the ledger

Filesystem grants are ACEs on host paths, so they outlive the process. glaipnir writes every
grant to `sessions/<id>/grants.ledger` *before* applying it. On the next run, entries no longer in
the policy are revoked; on `session delete` (and after ephemeral runs) all of them are. Grants use
`SET_ACCESS`, so changing a rule from `write` to `read` really removes write access, and they never
include `WRITE_DAC`/`WRITE_OWNER`.

Granting a large directory tree is slow the first time (Windows propagates the ACE to every
child). Later runs detect an identical grant and skip the rewrite.

Paths you cannot change the ACL of (for example under `C:/Program Files`) are accepted for `read`
when a package-wide ACE already allows it; otherwise the run is refused.

## Known limitations

These are properties of AppContainer itself, not bugs in glaipnir:

- **Baseline readable locations.** Every AppContainer can read anything that grants
  *ALL APPLICATION PACKAGES*: most of `C:/Windows` and `C:/Program Files`. Nothing in your
  profile grants it. Set `less_privileged = true` (LPAC) to remove this baseline.
- **Drive roots are not accessible.** `dir C:\` fails, and so does cmd.exe when told to start a
  program by absolute path. Pass `PATH` and start programs by name.
- **`NUL` cannot be opened.** The null device does not grant AppContainers access, so
  `> NUL` redirections and tools that write to it (including some git operations) fail. A
  restricted-token backend (planned) does not have this problem.
- **No filtered network yet.** AppContainers cannot connect to loopback without an
  administrator-installed exemption, which the proxy design needs. Until that path exists,
  `network.mode = "proxy"` is refused rather than downgraded.
- **Batch files are refused.** `cmd.exe` re-parses arguments to `.bat`/`.cmd` with its own
  rules, so safe quoting is impossible. Run `cmd /c script.cmd` explicitly if you accept that.
- **Pause** suspends every thread in the job; a thread the agent had itself suspended will be
  resumed by `resume`.

## Not implemented yet

- `windows_sandbox` backend (Hyper-V; not available on Home editions anyway).
- Restricted-token + synthetic write-SID backend for maximum tool compatibility.
- WFP rules binding the sandbox to the proxy port.
- Encryption at rest for snapshots (EFS is unavailable on Home editions).
