# AI research loop in 0.4

Version 0.4 adds persistent hypotheses, reproducible experiments, unverified
assessments, bounded model context, and explicit research imports between
sessions in the same store. It uses the existing Windows tools and isolated
research workers. Manual commands require no model or credentials.

## Model-driven investigations

Use the existing command and any configured OpenAI, Anthropic, or Ollama profile:

```text
investigate SESSION PROFILE GOAL
```

The orchestrator supplies the native and session tools together. For a research
goal, it asks the model to collect observations, record a testable hypothesis,
run an experiment with an expected outcome, assess the measurements, and choose
the next step. The model can also complete a simple inspection without inventing
a hypothesis. Tool availability does not guarantee a particular model will use
the workflow correctly; the harness validates references and execution itself.

Hypotheses, experiments, assessments, native tasks, observations, and artifacts
are separate records. Native results include `task_id`, `observation_id`, and
`artifact_id`; experiment results additionally include `experiment_id`.
Use these IDs as evidence references rather than treating narrative text as a
measurement. Tool errors are returned to the model so it can adjust its next step.

Each experiment executes exactly one existing native tool. The controller
validates the hypothesis and native arguments, transactionally links the
experiment to its queued task, and then schedules execution. An experiment
cannot invoke another experiment or a session-management tool. Native tasks
retain their existing deadlines, cancellation, process ownership, and evidence.

Hypothesis status is `open` until assessed. Later assessments derive its current
status as `supported`, `refuted`, or `inconclusive`, in recorded order. Assessments
must cite terminal experiments belonging to that local hypothesis. They are
model or researcher interpretations, always `verified:false`; neither a
supported hypothesis nor a measured crash/replay creates a verified finding.

An investigation defaults to 32 model turns and 32 experiments per invocation.
Every recorded experiment counts, including a failed or interrupted one.
Repeated manual commands each explicitly request one experiment; they do not
share an investigation budget. Exhaustion stops or rejects further work while
preserving completed records. HTTP retry behavior is unchanged; native
experiments are never automatically retried.

## Manual operations and schemas

All commands below also work in `shell`. JSON arguments can be inline or in an
`@FILE`. `tools list` publishes the same schemas used by model and manual dispatch.

| Command | Equivalent session tool or behavior |
| --- | --- |
| `hypothesis create ID JSON\|@FILE` | `hypothesis_create` |
| `hypothesis assess ID JSON\|@FILE` | `hypothesis_assess` |
| `hypothesis list ID` | `research_records` filtered to hypotheses |
| `hypothesis show ID RECORD_ID` | `research_record_get` |
| `experiment run ID JSON\|@FILE` | `experiment_run` |
| `experiment list ID` | `research_records` filtered to experiments |
| `experiment show ID RECORD_ID` | `research_record_get` |
| `research records ID [JSON\|@FILE]` | Page research record summaries |
| `research show ID RECORD_ID` | Read a research record |
| `research context ID` | Inspect bounded current research state and latest checkpoint ID |
| `research import DESTINATION SOURCE JSON\|@FILE` | Explicitly snapshot selected source research |

The session tools are also available through `tool run`:

| Tool | Arguments |
| --- | --- |
| `hypothesis_create` | `text`, optional `observation_ids` |
| `experiment_run` | `hypothesis_id`, `tool`, `arguments` object, `expected_outcome` |
| `hypothesis_assess` | `hypothesis_id`, `experiment_ids`, `conclusion`, `status` |
| `research_records` | Optional `kind`, `offset`, `limit` |
| `research_record_get` | `record_id` |
| `evidence_read` | `artifact_id`, optional `offset`, `length` |

Text fields accept 1..16384 UTF-8 bytes; record IDs accept 1..128 bytes.
Reference arrays accept at most 100 IDs; assessments require at least one
experiment. Hypotheses may cite only observations in the current session.
Experiment arguments are capped at 256 KiB and must match the selected native
tool's schema. Imported hypotheses cannot be modified or directly experimented
on: create a local hypothesis citing the imported observations first.

Record pages default to 20 entries, at most 100. Pass the returned `next_offset`
unchanged to continue, retaining the same `kind` filter. Supported kinds are
hypothesis, experiment, assessment, observation, artifact, crash, context import,
context checkpoint, task, and summary; use underscore-separated names such as
`context_import` in JSON. Large session-tool responses are archived with a
hash-checked `artifact_id` instead of being silently discarded.

`evidence_read` verifies the recorded file size and SHA-256, rejects reparse
points, and reads 1..65536 bytes (default 4096). It returns hex, text, offset,
byte count, and truncation information. The artifact ID must belong to the
current session. Its path resolves inside the store, independently of the
target working directory. Altered evidence is an error, not fresh evidence.

For example, after recording a hypothesis:

```json
{
  "hypothesis_id": "REPLACE_WITH_HYPOTHESIS_ID",
  "tool": "file_sha256",
  "arguments": {"path": "C:/Research/fixture.exe"},
  "expected_outcome": "A measured hash to compare with the earlier observation"
}
```

Pass this object to `experiment run SESSION @experiment.json`, then cite the
returned `experiment_id` when recording an assessment.

## Persistent context and continuation

Original messages and provider-native continuation data remain in history.
Before each model request the context builder combines the current goal, policy,
target identity, bounded research state, and recent complete exchanges. Stored
research, imported material, and tool output are labeled untrusted evidence.
Active local hypotheses and recent assessments take priority over observation
summaries; omitted details remain available through paged record queries.

The defaults in `limits` are:

```json
{
  "max_turns": 32,
  "max_experiments": 32,
  "context_budget_bytes": 1048576,
  "context_recent_exchanges": 8
}
```

The context budget measures the serialized normalized messages, including native
continuation blocks. It excludes tool schemas and provider envelope overhead;
the complete serialized provider request still has the independent 8 MiB limit.
Allowed context budgets are 4096 bytes through 4 MiB; recent-exchange limits are
1..64, and experiment limits are 1..1000.

At most the configured recent exchanges are retained, with more archived from
the request if needed to fit. Retained native blocks stay intact, and an
assistant's tool calls stay paired with their results. Large tool presentations
are replaced with bounded references to complete, persisted artifacts. These
projections are reused rather than repeatedly copying the same output. A goal
or other required context that cannot fit stops explicitly before HTTP.

Checkpoints record retained message IDs, archived-exchange counts, research
state, provider, goal, and byte budget. Their construction is deterministic and
requires no summarization API call. Detailed history remains queryable and
exportable. On restart, context is rebuilt from that history and current research
records, with legacy conversations supported. Choosing another model profile
uses the adapter's existing normalized-history conversion; provider-native
blocks remain stored in their original form.

Reopening finalizes unfinished tasks and linked experiments as interrupted. It
also supplies error results for unresolved model calls. Continuing an
investigation never implicitly executes an interrupted experiment again.

## Explicit imports between sessions

Research import is a manual command, not a model tool. Both sessions must already
exist in the same store, and they must differ. Pass selected record IDs:

```json
{"record_ids": ["REPLACE_WITH_SOURCE_RECORD_ID"]}
```

Selection accepts hypotheses, experiments, assessments, observations, tasks,
artifacts, crash records, and prior context-import records. It includes their
linked dependency closure: related hypotheses, experiments, assessments,
observations, tasks, and task artifacts. This can include sibling experiments
needed to retain the hypothesis's research history. Unfinished source tasks or
experiments cannot be snapshotted.

Imports accept at most 100 selected records, 4096 records after dependency
expansion, 8192 artifact files, and 288 MiB of artifact bytes. Source artifacts
and required record links must be intact. Evidence paths cannot escape their
source session. Artifacts
are verified, copied into the destination task's evidence directory, and
verified again. IDs and store-relative evidence paths are remapped while
source ordering, target identity, timestamps, original IDs, and previous import
provenance are retained. Original evidence file contents remain unchanged.

The snapshot is published transactionally only after validation and copying
succeed. Failure or cancellation exposes no partial research snapshot; copied
bytes remain explicit task evidence. Reopening an interrupted import preserves
raw files without deriving local crash records from copied source manifests.
Importing never executes a source operation or copies target executables unless
one was already an explicitly registered evidence artifact.

Imported records are immutable snapshots and remain unverified. File targets
match by their captured SHA-256; other target types require matching captured
identity and computer name. Other imports are marked `background:true` so
research from another target is not presented as a local measurement.
Background status is retained through further imports, even when the intermediate
session's target matches the new destination.
Destination exports include their own copies of the evidence and do not depend
on source artifact files remaining available.

Importing exported directories or a different store, shared automatic memory,
kernel integration, AD workflows, and streaming are outside version 0.4.

## Validation

The research-loop suite uses scripted responses through all three adapters to
exercise hypothesis creation, actual native experiments, assessments, a next
experiment, restart, and provider switching. It also covers budgets, incomplete
replies, reference validation, native failures, artifact tampering, compaction,
checkpoint reuse, import ordering/provenance, different-target snapshots,
independent exports, and interruption recovery. The CLI suite exercises manual
and interactive research operations. Existing x64 and WOW64 backend suites remain
part of Debug and Release validation. Tests require no credentials or live model
service; optional live model checks remain separate.
