# Windows analysis in 0.2

All tools run through the same native scheduler, observation store, and artifact
export path. They are available manually and to OpenAI, Anthropic, and Ollama.
The new tools inspect local objects without modifying them. Existing process
launch and shell execution capabilities remain available.

## Session targets

```text
session create PATH
session create --type file PATH
session create --type process PID
session create --type service NAME
session create --type registry KEY [--view native|32|64]
session create --type machine
```

Registry keys use `HKCU`, `HKLM`, `HKCR`, `HKU`, or `HKCC`, or their full hive
names, followed by a backslash and subkey. Hive names are case insensitive.
Remote registry connections are not supported. `native` selects the x64 view;
32/64 view flags have no effect on keys Windows shares between views.

Every new session contains a typed `target_info` alongside the existing display
string `target`. File targets retain a path and SHA-256; process targets retain
`pid` and `creation_time`; service targets retain `name`; registry targets retain
`key` and resolved `view`; machine targets describe the local host in session
metadata. Non-file sessions capture the creation-time current working directory.

Process creation times are decimal FILETIME strings. Native process inspection,
token inspection, and security tools automatically bind a matching selected PID
to the process session's creation time. Supplying a different identity returns an
error. Exited or reused targets fail rather than following a new process. Other
explicitly selected PIDs remain inspectable; the target provides context and
identity, rather than an access boundary. Shell commands do not perform this
native process identity binding.

Existing 0.1 sessions are interpreted as file targets on read. SQLite schema
version 1 and original session records remain unchanged; creation version and
historical hashes are preserved. Exports include normalized target metadata.

## Tool arguments

Use `tools list` for complete JSON schemas. All process IDs and access masks are
unsigned 32-bit integers. Process IDs must be nonzero.

| Tool | Arguments |
| --- | --- |
| `process_list` | optional `offset`, `limit` |
| `process_info` | `pid`, optional `creation_time` |
| `process_modules` | `pid`, optional `creation_time`, `offset`, `limit` |
| `process_threads` | `pid`, optional `creation_time`, `offset`, `limit` |
| `service_list` | optional `offset`, `limit` |
| `service_info` | `name` (service name, not display name) |
| `registry_list` | `key`, optional `view`, `offset`, `limit` |
| `registry_read` | `key`, `name`, optional `view`; empty name selects the default value |
| `token_info` | optional `pid`, `creation_time`; omitted PID selects the harness process |
| `security_descriptor` | `target` selector |
| `security_access_check` | `target`, `access_mask`, optional `token_pid`, `token_creation_time` |

Security target selectors are objects with a `kind` and its corresponding
locator: `{"kind":"file","path":"C:\\example"}`,
`{"kind":"process","pid":1234}`, `{"kind":"service","name":"EventLog"}`,
or `{"kind":"registry","key":"HKCU\\Software","view":"64"}`. Process
selectors also accept `creation_time`; registry selectors accept `view`.
File selectors support both files and directories.

Process details include PID, parent PID, name, image path, creation time,
architecture, session ID, and thread count. Modules include path, base address,
and image size. Threads include IDs and base/delta priorities. Processes may exit
or unload modules while being inspected; per-item errors retain available data.

Services include Win32 services and drivers. Inspection returns raw Windows
status/type/startup constants, PID, executable command line, account, dependencies,
and description. Enumeration reflects only services visible to the current
identity; Windows can omit services the caller cannot query.

Registry enumeration visits immediate subkeys, then value metadata, without
recursion. Reads preserve native type, raw hex, and decoded strings, multi-strings,
DWORD/QWORD numbers, or binary data. Expandable strings remain unexpanded.
Malformed values retain raw bytes and a `malformed` indicator. Oversized values
fail explicitly with `ERROR_INSUFFICIENT_BUFFER`; they are not decoded from
incomplete data.

Token results include the user SID, group/restricted/capability SIDs and
attributes, privilege names and state, integrity, elevation, token type, and
restriction/AppContainer flags. SID strings are authoritative; account-name
resolution and its potential domain lookups are not performed.

## Paging, errors, and privileges

List tools default to 256 entries, accept at most 4096 per call, and honor the
configured `output_limit` in serialized bytes. `items`, `offset`, `next_offset`,
and `truncated` describe each result. Continue using `next_offset` until it is
null. If even one item cannot fit, increase `output_limit`; the tool returns an
explicit error instead of a continuation that makes no progress.

Each call observes a live system. Paging across separate calls does not provide
a stable snapshot; processes, services, modules, or registry entries can change.
`partial` and `errors` distinguish incomplete fields or enumeration from complete
results. Native errors include `operation`, numeric `error_code`, and a message.
An allowed/denied access decision is distinct from an API failure.

The existing operation timeout and cancellation signal apply. Native inspection
checks cancellation between Windows API calls; a running synchronous API call
must return before the worker can stop. Process launch cancellation continues to
terminate its Job Object. No new tool changes services, registry values, tokens,
or ACLs.

By default the application leaves privileges unchanged. Explicitly pass
`--enable-debug-privilege` to enable an already-held SeDebugPrivilege. Failure to
hold it stops startup; enabling it does not bypass every Windows protection.
Its previous state is restored on exit. Evidence records effective identity,
integrity, elevation, and requested/enabled debug state. Full SACL inspection,
automatic elevation, and token impersonation of application threads are excluded.

## Descriptor and access-check results

Descriptor inspection returns owner/group SIDs, SDDL when convertible, DACL
state/protection flags, and ACEs in their original order. Common ACEs retain
mask, flags, SID, and inheritance information; every ACE retains raw bytes.
Unknown types remain visible. Absent/null DACLs and empty DACLs are distinct.

Access checks use Windows `AccessCheck` with a duplicated impersonation token
and object-specific generic mappings. The harness thread is never impersonated.
Results include `requested_mask`, `mapped_mask`, `granted_mask`,
`access_allowed`, the mapping used, and `actual_open_guaranteed:false`.
Conditional and object-specific ACEs return `ERROR_NOT_SUPPORTED` rather than an
unsupported access decision. Descriptors remain inspectable separately.

The result describes descriptor/token discretionary access. An actual operation
can still fail due to mandatory integrity, protected-process restrictions,
sharing rules, races, or other Windows controls. It is evidence for an
investigation, and is not automatically classified as a verified finding.

```powershell
$harness = Resolve-Path ./out/build/windows-x64/Release/glAIpnir.exe
$session = (& $harness --json session create --type machine | ConvertFrom-Json).session_id
@{target=@{kind='file'; path="$env:WINDIR/System32/notepad.exe"}; access_mask=1} |
    ConvertTo-Json | Set-Content -Encoding utf8 ./out/access.json
& $harness tool run $session security_access_check '@out/access.json'
& $harness --config config.local.json investigate $session local 'Inspect my token and list local services. Separate observations from hypotheses.'
```

API references: [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck),
[mandatory integrity](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control),
[service security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
[registry views](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view).
