# Research backend in 0.3

Version 0.3 supplies Windows user-mode debugging, basic mutation fuzzing, and
crash collection from the roadmap. Manual and model-directed operations use the
same tool registry, scheduler, session history, and evidence store. Results remain
observations; reproducing a process failure does not create a verified finding.

## Build and install

Build with the normal Windows x64 preset. The required `glAIpnir-dump32.exe`
helper is built from the local `cmake/wow64` project using the VS Win32 toolchain.
No additional downloads or debugger installation are required. Windows supplies
DbgHelp. Install with:

```powershell
cmake --build --preset release
cmake --install out/build/windows-x64 --config Release --prefix out/package
```

Keep `glAIpnir.exe`, `glAIpnir-worker.exe`, and `glAIpnir-dump32.exe` together in
`bin`. The latter two are private worker executables; `--version` is available for
installation checks. Normal use goes through the harness CLI. Release binaries
use the Visual C++ 2022 runtime; a machine without VS needs the x64 redistributable.

For the additional WOW64 regression suite, first configure the standalone test
project with `cmake -S tests/targets -B out/build/research-x86 -G "Visual Studio 17 2022" -A Win32`.
The main preset detects it and builds/tests both target architectures. CI includes
this configuration. The optional fixture is distinct from the required dump helper.

## Bounded debugging

Create a file or process session using the existing commands, then use a JSON
file with `debug run SESSION @arguments.json`, `debug attach SESSION @arguments.json`,
or the equivalent `tool run` names. `tools list` prints exact schemas.

`debug_run` requires `executable` and an `arguments` string array. Optional fields:

| Field | Default and behavior |
| --- | --- |
| `working_directory` | Session directory; relative executable paths resolve here |
| `stdin_file` | No input; an explicit file is copied into evidence and redirected as stdin |
| `timeout_ms` | 5000 ms, bounded by the outer operation deadline |
| `entry_breakpoint` | `true`; capture the executable entry point |
| `breakpoints` | Up to 32 one-shot `{rva,module?}` entries; omitted module selects the main executable |
| `step_count` | 0; capture up to 32 instruction steps after each breakpoint |
| `stop_on_breakpoint` | `false`; when true, finish after the requested steps and terminate the owned target |
| `memory_reads` | Up to 16 `{address,length}` entries, at most 4096 bytes each |
| `max_events` | 1024 retained events, allowed range 16–4096 |
| `dump_on_crash` | `true`; preserve an exception minidump |
| `artifact_limit` | 64 MiB, allowed range 1 KiB–256 MiB |

Module names are case-insensitive filenames. RVAs must lie inside the loaded
module when its image size is available. Breakpoints restore their original
instruction before continuing and are not reinserted. Unresolved requested
modules are reported. Stepping temporarily suspends other observed threads and
restores those suspension counts. These are bounded investigations, not persistent
interactive debugger connections across CLI invocations.

Snapshots include integer/control registers, module-relative instruction and
stack locations, instruction/stack bytes, and requested memory ranges. Failed
memory reads retain their status and any readable bytes. Stack walking uses local
DbgHelp without symbol-server downloads; source-level debugging and disassembly
are outside this milestone.

The event history distinguishes handled first-chance events from unhandled
exceptions. Only the latter create crash records. ANSI and Unicode debug output
are recorded. Normal nonzero exit codes remain exits, not inferred crashes.

`debug_attach` requires `pid` and optionally accepts `creation_time`, `monitor_ms`
(default 1000), `memory_reads`, `max_events`, and `dump_on_crash`. It collects up to
16 thread snapshots at the initial debugger stop, monitors events, and detaches.
It does not install software breakpoints or terminate an existing target.
Process-session identity binding from 0.2 applies automatically.

Launched programs are owned by a kill-on-close Job Object; their descendants are
cleaned up on completion, timeout, cancellation, or controller exit. Attached
programs stay outside that owned job. Research workers are themselves isolated in
a controller-owned job. No privilege is enabled unless the existing explicit
`--enable-debug-privilege` option is used. Jobs control lifetimes and are not a
security sandbox.

## Mutation campaigns

`fuzz_run` requires `executable`, `arguments`, and `corpus` (a directory of seed
files). File mode requires `{input}` somewhere in an argument; the placeholder is
replaced with the preserved case file. `input_mode:"stdin"` redirects that case
to stdin instead. Argument arrays are quoted directly for `CreateProcessW` and
are not shell commands.

| Field | Default and behavior |
| --- | --- |
| `iterations` | 100, maximum 1000 |
| `random_seed` | 0; fixed MT19937 engine and mutation version 1 |
| `max_input_bytes` | 4096, maximum 1 MiB |
| `case_timeout_ms` | 1000, maximum 60000 |
| `max_crashes` | 16 unique signatures, maximum 64 |
| `stop_on_crash` | `false` |
| `dictionary` | Up to 64 UTF-8 strings, each at most 1024 bytes |
| `artifact_limit` | 64 MiB for the campaign |
| `working_directory` | Session directory |

The corpus contains at most 128 immediate regular files, sorted by path and
deduplicated by SHA-256. Oversized seeds are reported and skipped; an empty usable
corpus is an error. Each seed is executed unchanged first. Later cases use
deterministic bit flips, byte replacements, insertion, deletion, duplication, or
dictionary insertion. This is mutation-based fuzzing without coverage feedback.

Each case runs in a fresh debuggee. The campaign separates completed cases,
nonzero exits, timeouts, and crashes. It preserves copied seeds, generated inputs,
hashes, per-case debugger evidence, and a started/completed journal. Executable
changes stop the campaign. Cancellation, deadlines, byte/count limits, or worker
failure preserve already-written evidence. Campaigns do not automatically resume.

Deduplication uses exception code, faulting module filename/RVA, and access kind
when available. Addresses outside known modules retain their absolute address
and are explicitly marked as not normalized. Repeated signatures share the
initial dump; each occurrence retains its own input and replay manifest.

Example request (replace the executable and seed directory with local paths):

```json
{
  "executable": "C:\\Research\\parser.exe",
  "arguments": ["--input", "{input}"],
  "corpus": "C:\\Research\\seeds",
  "iterations": 100,
  "random_seed": 123,
  "case_timeout_ms": 1000
}
```

Run it with `fuzz run SESSION @campaign.json`.

## Collection, inspection, and replay

`dump_process` accepts `pid`, optional `creation_time`, and `artifact_limit`. It
creates a live-process snapshot without fabricating an exception. For WOW64
targets, the x86 helper writes the dump with the target's context format.

`crash_info` accepts a minidump `path`. It bounds-checks directories and relevant
streams and returns architecture, exception/context information, threads, and
modules. The reader runs in a worker process. Normal snapshots have
`has_exception:false`; collection failures and partial dumps remain explicit.

`crash list SESSION` lists persisted records; `crash show SESSION RECORD_ID`
reads one. A result's `artifact_root` is relative to the store or exported root;
paths such as `minidump`, `manifest`, and `reproducer` are relative to that root.

`crash_replay` requires a `manifest` pointing to `reproducer.json`. It verifies
the executable and any preserved input hashes, reruns the case, and compares the
expected signature. Optional `executable`, `working_directory`, and `timeout_ms`
overrides support moving an export; an executable override must have the same
hash. `reproduced` is a measured result, not a vulnerability classification.
The worker starts in its task workspace, so an override can replace a session
directory that no longer exists.

Fuzz manifests use paths relative to their preserved input. Standalone debugger
runs preserve explicit stdin and otherwise retain literal arguments; arbitrary
external files referenced by those arguments must still be supplied. Attached
programs do not have a captured launch command, so their records have no automatic
launch reproducer.

## Persistence and limits

Task workspaces live under `artifacts/SESSION/TASK`. Generated files are
registered transactionally with their size and SHA-256, alongside observations,
task results, and crash records. Exports verify and copy binary evidence as well
as JSON. SQLite remains at schema version 1, and existing sessions stay readable.

Outputs include the request, worker identity/log, result, debugger reports, raw
stdout/stderr, minidumps, and replay metadata. Campaigns additionally include
copied seeds, case inputs, and a journal. Large tool responses are summarized
while detailed files remain in evidence. The store indexes saved crash manifests
even when a response's catalog is truncated.
Summarized results reference `full_result.json` only after it has been saved.
If the artifact budget or an I/O error prevents preserving the full response,
the task fails with `evidence_incomplete:true` and an explicit error;
`operation_ok` retains the underlying operation's status. Already saved files
remain available as evidence.

The existing global operation deadline applies to the whole worker invocation.
Cancellation first requests cooperative cleanup; the controller terminates a
worker job if it does not finish within five seconds. Minidump writes honor a
byte budget and cancellation. Artifact registration caps the task at 8192 files
and 288 MiB including control files. On reopening an interrupted task, available
files are registered without rerunning the target. Active worker identity is
checked before recovery reads its files.
Partial or malformed worker identity files and crash manifests remain registered
as raw evidence, with their paths and errors in `evidence_warnings`. Valid crash records are still
indexed, and the task becomes `interrupted`; reopening the store does not
repeat execution or duplicate the recovered records.

The test suites cover both architectures, step/context integrity, handled events,
owned/attached process lifetimes, hash-checked replay, deterministic inputs,
timeouts, cancellation, partial metadata recovery, replay after moving the
original directory, response preservation failures, and complete CLI/export workflows.
Provider tests exercise the research tool through all three HTTP adapters using
local fixtures; no real model credentials or API calls are required.

Implementation references: [Windows debugger loop](https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop),
[debug events and handle ownership](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent),
[minidump writer](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump).
