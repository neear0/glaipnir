# glAIpnir 0.2

A Windows-native C++20 research harness with persistent sessions, native tools,
and model-driven task dispatch. Research direction and conventions are in
[coms.md](glAIpnir/coms.md). Version 0.2 adds process, service, registry, token,
and security descriptor inspection to the native runtime. Debugging, fuzzing,
crash triage, kernel integration, and AD assessment come later.

## Build

Requires Windows 10 (1709 or later)/11 x64, Visual Studio 2022 with Desktop development with C++,
Windows SDK, and CMake 3.24+. Open this folder in Visual Studio, select the
`windows-x64` preset, and build. CMake is the authoritative build definition.

```powershell
cmake --preset windows-x64
cmake --build --preset debug
ctest --preset debug
cmake --build --preset release
ctest --preset release
```

The executable is `out/build/windows-x64/Release/glAIpnir.exe`.
The first configure downloads pinned source archives with SHA-256 verification:
nlohmann/json 3.12.0 (MIT) and SQLite 3.54.1 (public domain). Both are statically
linked into the application. Windows supplies WinHTTP and CNG; no model SDK,
Python runtime, or third-party service is required for manual tools or tests.

For an offline build, extract the same verified archives locally and configure
with `-DFETCHCONTENT_SOURCE_DIR_JSON=<json-directory>` and
`-DFETCHCONTENT_SOURCE_DIR_SQLITE=<sqlite-amalgamation-directory>`.

## First investigation

Copy [examples/config.json](examples/config.json) to `config.local.json`. Replace
the model placeholder in the profile you want to use with a tool-capable model
available to you. Endpoints are full API URLs. Credentials come from the named
environment variable; do not put keys in configuration files.

```powershell
$harness = Resolve-Path ./out/build/windows-x64/Release/glAIpnir.exe
$created = & $harness --json session create "$env:WINDIR/System32/notepad.exe" | ConvertFrom-Json
$session = $created.session_id
& $harness --config config.local.json investigate $session local 'Inspect the PE headers and hash. Summarize observations and remaining hypotheses.'
& $harness --json session show $session
& $harness session export $session ./notepad-investigation
```

The same session ID works after restarting the executable. Export destinations
must not already exist. `history.json` contains the session and ordered evidence;
`reproduction.json` records operations, working directories, limits, and results.
Artifacts are copied and hash-checked. Target binaries are not copied. Commands
are never automatically replayed on reopen or export.

Optional live smoke checks use the configured providers and can incur API usage:

```powershell
& $harness --config config.local.json investigate $session openai 'Use file_metadata on the target, then summarize.'
& $harness --config config.local.json investigate $session anthropic 'Use file_sha256 on the target, then summarize.'
& $harness --config config.local.json investigate $session local 'Use pe_headers on the target, then summarize.'
```

Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in your environment before invoking
those profiles. Ollama runs locally and needs an installed tool-capable model.

## Manual tools and interactive use

```powershell
& $harness tools list
@{path="$env:WINDIR/System32/notepad.exe"} | ConvertTo-Json | Set-Content -Encoding utf8 ./out/metadata.json
& $harness tool run $session file_metadata '@out/metadata.json'
& $harness --config config.local.json shell
```

The prompt accepts the same `session`, `tools`, `tool`, and `investigate` commands.
Use `help` or `exit`. Quote arguments containing spaces; use `@FILE` for JSON
arguments to avoid nested shell quoting. Commands can also be piped into `shell`.

| Command | Purpose |
| --- | --- |
| `session create TARGET` | Capture a local file target and its SHA-256 |
| `session list` | List stored sessions |
| `session show ID` | Read session configuration and ordered evidence |
| `session export ID DIRECTORY` | Export evidence and reproduction instructions |
| `tools list` | Show tool names and JSON argument schemas |
| `tool run ID TOOL JSON\|@FILE` | Execute a native tool without a model |
| `investigate ID PROFILE GOAL` | Run or continue a model-driven investigation |
| `shell` | Start the persistent command prompt |

Global options: `--store PATH` (default `.glaipnir`), `--config FILE`, `--json`
(compact JSON), and `--enable-debug-privilege`. Diagnostics go to stderr. Exit codes: 0 success, 1 failure, 130
cancelled operation. Interactive command errors leave the prompt running.

## Windows analysis

Sessions can directly target a process, service, registry key, or the local
machine. File-session commands from 0.1 remain supported.

```powershell
& $harness session create --type process $PID
& $harness session create --type service EventLog
& $harness session create --type registry 'HKCU\Software' --view 64
& $harness session create --type machine
```

Use the returned session ID with `tool run`, `investigate`, `session show`, or
`session export`. Process sessions record PID and creation time to detect PID
reuse. File sessions use the target directory; other sessions capture the CLI's
current directory. All target types work in the interactive prompt.

The new tools are `process_list`, `process_info`, `process_modules`,
`process_threads`, `service_list`, `service_info`, `registry_list`, `registry_read`,
`token_info`, `security_descriptor`, and `security_access_check`.
See [Windows analysis](docs/windows_analysis.md) for arguments, examples, paging,
permission semantics, and compatibility details. `tools list` prints the exact
schemas supplied to all three model adapters.

Inspection uses current privileges by default. `--enable-debug-privilege`
explicitly enables an already-held SeDebugPrivilege for the invocation, restores
its previous state on exit, and fails clearly when that privilege is unavailable.
It does not elevate the process. Session and task evidence record the effective
user, integrity, elevation, and requested/enabled debug privilege state.

Available tools:

| Tool | Arguments |
| --- | --- |
| `file_metadata` | `path` |
| `file_sha256` | `path` |
| `file_read` | `path`, optional `offset`, `length` (default 4096) |
| `pe_headers` | `path` |
| `process_launch` | `executable`, `arguments` array, optional `working_directory` |
| `shell_execute` | `command`, optional `shell` (`powershell` or `cmd`), `working_directory` |

Relative tool paths resolve against the session working directory; relative export destinations
and CLI JSON files resolve against the CLI's current directory. Program launches
require an executable path, without implicit PATH searching. File reads include
hex bytes and text; process results retain bounded raw output as hex in artifacts.
Text containing invalid UTF-8 uses replacement characters. PE inspection reads
at most 1 MiB of headers and rejects malformed or larger header layouts.

## Execution and storage behavior

Model tool calls run autonomously under the current Windows identity. The
selected target establishes context and a working directory; it does not restrict
shell commands or file access. The harness does not elevate privileges or provide
a security sandbox. Job Objects manage child lifetimes, timeouts, and cancellation.
PowerShell runs with `-NoProfile -NonInteractive`; cmd runs with `/d /s /c`.

Defaults are 60 seconds per operation, 1 MiB per output stream or file read,
120 seconds per HTTP attempt, and 32 model turns per investigation. Ctrl+C
cancels the current investigation and its running child processes. Output is
drained after its capture limit to prevent pipe deadlocks; results identify
truncation, timeout, and nonzero exits. Each response may request up to 64 tools,
executed sequentially by a FIFO worker. HTTP transient failures receive at most
two retries; native operations are not automatically retried. Remote model
endpoints require HTTPS; HTTP is permitted for loopback servers.

SQLite uses schema version 1, WAL, full synchronization, and a single-writer
runtime lock. One process owns a store at a time. Reopening marks unfinished
tasks interrupted and supplies error results for unresolved model calls. All
completed evidence remains available. Model summaries are explicitly unverified;
there is no automatic promotion to verified findings. Conversations are bounded
to an 8 MiB request and HTTP responses to 16 MiB; exhausted budgets stop the run
with evidence preserved. Context compaction and streaming are deferred.
Existing 0.1 sessions are normalized as file targets when read, preserving their
original database records and creation-version provenance. No migration is needed.

Provider history preserves OpenAI reasoning items and encrypted continuation,
Anthropic content blocks and grouped tool results, and Ollama assistant messages.
See [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling),
[Anthropic tool results](https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls),
and [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling).

## Validation

CTest uses harmless Windows fixture processes and an HTTP server bound to
loopback. It exercises native tools, process limits and descendant cleanup,
provider authentication and continuation, transient HTTP failures, cancellation,
session recovery, artifact tampering, and complete investigations and exports for
all three adapters. Tests require no credentials and make no external API calls.
The Windows analysis suite also uses temporary HKCU registry keys, owned fixture
processes, controlled ACLs and duplicated tokens, and read-only service inspection.
It tests typed sessions, PID identity checks, privilege restoration, registry
decoding, and legacy compatibility without requiring elevation. A sandbox must
allow those temporary registry writes. Installed services are never modified.
Windows CI builds and tests Debug and Release and checks the install package.
Live provider smoke checks are optional and separate from the default suite.
