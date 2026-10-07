# Policy reference

A policy is a TOML file. glaipnir reads a strict subset of TOML: `[table]` headers,
`key = value`, strings (`"basic"` with escapes, `'literal'` without), decimal integers,
booleans, and arrays of strings. Inline tables, dotted keys, floats, dates and multi-line strings
are rejected. Unknown tables or keys are errors.

On Windows, write paths with forward slashes (`"C:/tools"`) or as literal strings
(`'C:\tools'`); in a basic string `"C:\tools"` the `\t` would be a tab.

Use `glaipnir policy check FILE` to validate a policy and print its normalized form and digest.
The digest is recorded in the audit log for every run.

## `[sandbox]`

| key | type | default | meaning |
|---|---|---|---|
| `name` | string | `"unnamed"` | label used in audit records |
| `backend` | string | `"auto"` | `auto`, `app_container`, `windows_sandbox`, `process`, `firecracker`; unimplemented backends are refused |
| `less_privileged` | bool | `false` | Windows LPAC: also drop the read access every AppContainer has to `C:/Program Files` and similar. Stricter, but most installed tools then need explicit `read` entries, and Program Files cannot be granted as a normal user |

## `[filesystem]`

| key | type | default | meaning |
|---|---|---|---|
| `read` | array of paths | `[]` | readable (and executable) by the sandbox, recursively |
| `write` | array of paths | `[]` | readable and writable, recursively |

The session workspace is always read-write and is the default working directory; it does not
need to be listed.

Paths must be absolute or start with `${cwd}` (the directory glaipnir was started from) or
`${home}`. They must exist; they are resolved through symlinks and junctions before checking.
Refused: drive/filesystem roots, the home directory and its ancestors, the glaipnir state
directory, and known credential locations, including anything that contains one (so
`${home}/AppData/Roaming` is refused because it contains `Microsoft/Credentials`).

## `[network]`

| key | type | default | meaning |
|---|---|---|---|
| `mode` | string | `"none"` | `none`; `proxy` (egress only through the filtering proxy, not implemented yet, refused at run time); `unrestricted` (direct internet access, prints a warning; on Windows private/LAN ranges are excluded by the AppContainer capability model) |
| `allow` | array | `[]` | `proxy` mode only: `"host"`, `"*.domain"`, optionally `":port"` (default 443). Lowercase host names only; IP literals are refused |

## `[env]` and `[env.set]`

The host environment is never inherited.

| key | type | meaning |
|---|---|---|
| `env.pass` | array of names | copy these variables from the host, if set |
| `[env.set]` | table of strings | set these variables to literal values |

Names that look like credentials (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, `*_KEY`,
`*CREDENTIAL*`, `*COOKIE*`, ...) and names starting with `GLAIPNIR_` are refused.

glaipnir always sets `GLAIPNIR_SESSION` and `GLAIPNIR_WORKSPACE`. On Windows it also provides
non-secret system variables (`SystemRoot`, `ComSpec`, `PATHEXT`, `ProgramFiles`, ...) and points
`USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA`, `TEMP` and `TMP` into the session's private
container folder. A policy can override any of these except the `GLAIPNIR_` ones.

## `[limits]`

Zero means unlimited.

| key | default | meaning |
|---|---|---|
| `memory_mb` | 4096 | total committed memory of the whole process tree |
| `max_processes` | 128 | concurrent processes (forced to 1 without `child_processes`) |
| `cpu_percent` | 100 | hard CPU cap across all cores, 1-100 |
| `wall_timeout_s` | 0 | kill the tree after this much real time (exit code 124) |
| `cpu_timeout_s` | 0 | kill the tree after this much user-mode CPU time |

## `[capabilities]`

All default to `false`.

| key | meaning |
|---|---|
| `child_processes` | may start subprocesses; they inherit every restriction and cannot leave the sandbox |
| `clipboard_read` / `clipboard_write` | clipboard access |
| `desktop_ui` | may interact with windows and global atoms it does not own |
