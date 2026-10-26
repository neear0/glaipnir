Good. Let's define the project properly, without getting distracted by authentication systems or business concerns.

I would treat this as a Windows-native, AI-driven vulnerability research and penetration-testing framework, written in modern C++, targeting professional security researchers first.

The goal isn't to create another chatbot that runs security commands. It's to create a research harness that can reason about Windows, investigate complex systems, operate debugging and analysis tools, and autonomously pursue promising research directions.

# 1. Project vision

> A fully native C++ harness for AI models, designed for autonomous Windows vulnerability research, exploitation research, system analysis, and professional penetration testing.

The project should have five defining characteristics:

1. Windows-first: Native Win32 and NT integration, not a Linux-first framework ported to Windows.
2. Model-agnostic: Support local and remote LLMs without tying the architecture to one provider.
3. Research-oriented: Capable of hypothesis generation, experimentation, crash analysis, and vulnerability investigation.
4. Modular: Different workflows, instrumentation engines, and target types can be added independently.
5. Professional-grade: Persistent research sessions, reproducible results, detailed evidence, and controllable execution.

# 2. The two main modes

Research Mode

Primary development priority

Investigate potentially unknown vulnerabilities.

Static and dynamic analysis, fuzzing, debugging, crash triage, research hypotheses, and reproducer generation.

Pentest Mode

Secondary development priority

Assess known weaknesses and misconfigurations.

Windows enumeration, privilege analysis, Active Directory analysis, attack-path investigation, and controlled exploitation.

These should be workflows, not independent implementations.

A research session could transition between workflows without losing collected evidence or understanding of the target.

# 3. Core architecture

CLI / Research Interface

Session management · Commands · Findings · Configuration

AI Orchestration Layer

Model adapters · Planning · Hypotheses · Context management

Native C++ Runtime

Scheduler · Session manager · Execution workers · Events · State

Analysis Engines

Fuzzing, debugging, memory analysis, crash triage

Windows Backends

Applications, processes, services, drivers, AD

Persistent Evidence & Research Storage

SQLite · Artifacts · Research history · Reproduction data

The key architectural rule is that the AI decides what to investigate, while native C++ components perform deterministic operations and collect evidence.

That also allows researchers to use the harness without AI for manual investigations.

# 4. Proposed repository structure

I'd keep the directory structure explicit and relatively flat initially.

```

windows_harness/
│
├── CMakeLists.txt
├── cmake/
├── include/
│   └── harness/
│       ├── core/
│       ├── ai/
│       ├── research/
│       ├── pentest/
│       ├── windows/
│       ├── backends/
│       └── storage/
│
├── src/
│   ├── main.cpp
│   │
│   ├── core/
│   │   ├── runtime.cpp
│   │   ├── scheduler.cpp
│   │   ├── session.cpp
│   │   ├── event_bus.cpp
│   │   └── worker.cpp
│   │
│   ├── ai/
│   │   ├── model_client.cpp
│   │   ├── orchestrator.cpp
│   │   ├── context.cpp
│   │   ├── reasoning.cpp
│   │   └── tool_dispatcher.cpp
│   │
│   ├── research/
│   │   ├── research_engine.cpp
│   │   ├── hypothesis_engine.cpp
│   │   ├── experiment_runner.cpp
│   │   └── crash_triage.cpp
│   │
│   ├── pentest/
│   │   ├── assessment_engine.cpp
│   │   ├── enumeration.cpp
│   │   ├── privilege_analysis.cpp
│   │   └── finding_validator.cpp
│   │
│   ├── windows/
│   │   ├── process.cpp
│   │   ├── memory.cpp
│   │   ├── security.cpp
│   │   ├── registry.cpp
│   │   ├── service.cpp
│   │   └── telemetry.cpp
│   │
│   ├── backends/
│   │   ├── application/
│   │   ├── user_mode/
│   │   ├── kernel/
│   │   └── active_directory/
│   │
│   ├── storage/
│   │   ├── database.cpp
│   │   ├── artifact_store.cpp
│   │   └── research_history.cpp
│   │
│   └── cli/
│       ├── cli.cpp
│       └── command_parser.cpp
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── targets/
│
├── examples/
├── docs/
└── third_party/

```

Headers would mirror the source tree. For example, `src/research/research_engine.cpp` corresponds to `include/harness/research/research_engine.hpp`.

I'd start with statically linked modules inside one executable, using separate worker processes for operations that require isolation. A dynamic plugin ABI can come later.

# 5. Your C++ coding conventions

I'd make these mandatory across the repository.

| Element         | Convention   | Example               |
| --------------- | ------------ | --------------------- |
| Variables       | `snake_case` | `target_process_id`   |
| Functions       | `snake_case` | `analyze_process()`   |
| Classes         | `c_` prefix  | `c_research_engine`   |
| Structs         | `_t` suffix  | `research_result_t`   |
| Enums           | `_t` suffix  | `research_mode_t`     |
| Filenames       | `snake_case` | `research_engine.cpp` |
| Constants       | `snake_case` | `max_worker_count`    |
| Private members | trailing `_` | `current_session_`    |
| Namespaces      | lowercase    | `harness::research`   |

And your namespace restriction:

Namespace blocks only in headers. C++ source files use fully qualified definitions.

For example:

research_engine.hpp

```

#pragma once

#include <string>

namespace harness::research {

enum class research_mode_t {
    vulnerability_research,
    penetration_test
};

struct research_target_t {
    std::string target_id;
    std::string target_path;
};

class c_research_engine {
public:
    void set_target(research_target_t target);

    const research_target_t& get_target() const noexcept;

private:
    research_target_t current_target_{};
};

}

```

research_engine.cpp

```

#include "harness/research/research_engine.hpp"

#include <utility>

void harness::research::c_research_engine::set_target(
    harness::research::research_target_t target
) {
    current_target_ = std::move(target);
}

const harness::research::research_target_t&
harness::research::c_research_engine::get_target() const noexcept {
    return current_target_;
}

```

No `namespace {}` blocks inside `.cpp` files. No `using namespace std;`. Namespace qualification remains explicit.

For internal file-local functions, I'd prefer `static` functions rather than anonymous namespaces to respect your convention.

One refinement I'd suggest: keep namespaces fairly shallow. `harness::research` and `harness::windows` are fine; five nested namespaces make this style unnecessarily verbose.

# 6. Core components and responsibilities

| Class                 | Responsibility                                |
| --------------------- | --------------------------------------------- |
| `c_runtime`           | Starts and manages the harness                |
| `c_task_scheduler`    | Schedules operations and manages dependencies |
| `c_research_session`  | Maintains the current investigation           |
| `c_model_client`      | Communicates with an AI model                 |
| `c_orchestrator`      | Coordinates reasoning and tool execution      |
| `c_research_engine`   | Manages vulnerability research                |
| `c_assessment_engine` | Manages penetration-testing workflows         |
| `c_windows_backend`   | Provides common Windows operations            |
| `c_experiment_runner` | Runs reproducible experiments                 |
| `c_crash_analyzer`    | Processes crashes and diagnostic evidence     |
| `c_evidence_store`    | Stores artifacts and observations             |
| `c_research_history`  | Preserves research context across sessions    |

I'd introduce a common data model immediately.

For instance, `observation_t`, `hypothesis_t`, `experiment_t`, `artifact_t`, and `finding_t` should be distinct.

A hypothesis generated by an AI must never silently turn into a verified finding. This separation is fundamental for professional research.

# 7. Development sequence

| Version | Focus                | Deliverable                                                              |
| ------- | -------------------- | ------------------------------------------------------------------------ |
| `0.1`   | Native runtime       | Windows executable, sessions, model integration, task dispatch           |
| `0.2`   | Windows analysis     | Processes, services, registry, tokens, security descriptors              |
| `0.3`   | Research backend     | User-mode debugging, basic fuzzing, crash collection                     |
| `0.4`   | AI research loop     | Hypothesis generation, experiments, results analysis, persistent context |
| `0.5`   | OS internals         | Kernel-debugging integrations and disposable VM research                 |
| `0.6`   | Pentest workflow     | Windows security assessment and AD analysis                              |
| `1.0`   | Professional release | Stable APIs, reproducible research, reporting, tests, documentation      |

A successful first milestone would be:

> Run the harness on Windows, select a local research target, connect an LLM, execute a structured investigation through native C++ components, collect observations, and preserve the entire session for reproduction.

Then add progressively more advanced debugging and vulnerability research capabilities.

## The design principle I'd establish from day one

Three independent systems:

- Harness: The runtime, scheduler, tools, storage, and Windows integrations.
- Intelligence: The AI reasoning, planning, hypothesis generation, and context management.
- Capabilities: The actual research and assessment modules, including debugging, instrumentation, fuzzing, and security analysis.
