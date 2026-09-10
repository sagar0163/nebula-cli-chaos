# Business Requirements Document (BRD)

## 1. Project Overview

- **Project Name**: nebula-cli-chaos
- **Type**: Chaos / resilience testing framework for CLI applications
- **Target Users**: developers and maintainers who ship command-line tools (any language)
  and want a repeatable, zero-infrastructure resilience check before release
- **Core Functionality**: run a configurable suite of chaos tests (concurrency, fuzz,
  memory/resource stress, fault injection) against a target CLI command and produce a
  pass/fail JSON report

## 2. Problem Statement

CLI tools fail in production the same way servers do — rate limits, malformed input,
concurrent bursts, DNS hiccups, disk pressure, OOM kills, and hangs — yet most CLI projects
have zero resilience testing. Existing chaos platforms (Toxiproxy, Chaos Mesh) target
networked services and require proxies, agents, or cluster access, which is disproportionate
for validating a single command-line binary. Developers need a lightweight way to catch
resilience failures in their CLI before customers hit them.

## 3. Product Goals

1. Make a proof-of-concept-grade resilience check for any CLI runnable in under a minute.
2. Require **zero infrastructure**: pure Node.js, no root, no system daemons, no external
   dependencies.
3. Produce a machine-readable report that can gate a CI pipeline.
4. Grow into richer experiment definitions and reporting over time, without breaking the
   core "point at a CLI, get a report" experience.

## 4. User Stories

| ID | As a… | I want to… | So that… |
|----|-------|-----------|----------|
| US-1 | CLI maintainer | run a full chaos suite against my command by default | I get a pass/fail resilience snapshot with one command |
| US-2 | CLI maintainer | run only a category (e.g. `--category=network`) | I can iterate quickly on one concern |
| US-3 | CLI maintainer | point the suite at my own binary without editing config | I can test any CLI immediately |
| US-4 | CI engineer | gate the build on the slate of shell-test results | regressions fail the pipeline (nonzero exit) |
| US-5 | CLI maintainer | inject latency, DNS failure, disk pressure, OOM, and kill | I can verify my error handling under realistic faults |
| US-6 | Developer | extend the suite with my own test methods | I can cover project-specific failure modes |
| US-7 | Reviewer / outsider | understand exactly what is implemented vs. planned | adoption expectations are honest |

## 5. Features & Behavior

**Implemented (v2.0.0)**
- Configurable test categories & per-test timeouts via `chaos.config.json`
- Concurrency / load tests: rapid-fire, extreme concurrency, zombie detection, fork-bomb input
- Fuzz tests: special chars, unicode, command injection, ReDoS, atomic-bomb patterns
- Memory / resource tests: large input, 1MB stdin, JSON bombs, heap-growth check
- Timeout / hang detection (slow-loris)
- Pure-Node.js fault injection: latency, DNS failure (direct + subprocess), disk pressure,
  OOM kill, process kill
- JSON report written to `chaos-report-<timestamp>.json`; nonzero exit on any failure
- CLI: `--help`, `--version`, `run <config>`, `--category=`, `--config=`, ad-hoc target command

**Not implemented / planned**
- YAML experiment definition language
- `nebula-chaos report --format html|json` subcommand (reports already emitted as JSON during runs)
- `nebula-chaos metrics` Prometheus/HTTP endpoint
- Automated recovery validation (retry/circuit-breaker/checkpoint assertions)
- Kernel-level network faults (packet loss, bandwidth shaping)
- Programmatic API surface beyond `require('./test-runner')`

## 6. Acceptance Criteria (release-gating)

A version may be released only when:

1. **AC-1**: `npm test` runs the full default suite against `chaos.config.json` and each test
   is either PASS or FAIL with a captured reason; the runner exits nonzero on any FAIL.
2. **AC-2**: `node chaos-runner.js --category=<name>` runs exactly the tests listed under that
   category in the config.
3. **AC-3**: A user can point the suite at their own CLI with
   `node chaos-runner.js path/to/cli` without editing config.
4. **AC-4**: Every fault-injection test degrades gracefully (no test leaves stray processes or
   temp files behind).
5. **AC-5**: The suite needs no network setup, no root, and no package beyond Node.js ≥ 16.
6. **AC-6**: Documentation (README, ARCHITECTURE.md) accurately distinguishes implemented
   capabilities from planned ones.
7. **AC-7**: A report is produced on every run with summary + per-test results and a stable
   JSON schema.

## 7. Success Metrics

- **Adoption**: time-to-first-report < 1 minute from `git clone` (measured as: number of
  steps a new user must follow in README Quick Start — target ≤ 4 commands).
- **Reliability-under-test**: the default suite detects at least 3 distinct classes of
  failure (concurrency, input fuzzing, resource exhaustion, injected faults) — i.e. coverage
  of ≥ 3 of the 4 chaos concerns.
- **Regression gating**: CI job green on clean code, red when a target CLI starts hanging or
  rejecting its own valid input (i.e. assertions actually couple to target behavior).
- **Documentation honesty**: zero README/ARCH doc claims that name a command or format the
  code does not implement (checked by review, since AC-6).
- **Zero-fault hygiene**: test runs never leave orphan processes or >1MB of leftover temp
  files on disk.
- **Maintainability**: adding a new test requires touching ≤ 2 files (`test-runner.js` +
  `chaos.config.json`) and no core-engine changes.

## 8. Roadmap (ordered)

1. Ground work: JSON experiment definitions → YAML (`experiment/name/faults/assertions`)
2. `nebula-chaos report --format html|json` producing the already-collected data
3. `nebula-chaos metrics` Prometheus endpoint
4. Recovery validation: retry/circuit-breaker/fallback + idempotency assertions
5. Optional OS-level network fault backends for users who can take root / install agents

## 9. Risks & Open Questions

- **Scope creep**: risk of becoming a general chaos platform and losing the "lightweight for
  CLIs" niche — mitigated by keeping the process-level target as the primary interface.
- **Publishing**: package not yet on npm; release flow and `npm publish` are stubbed in CI and
  blocked on an NPM token.
- **Portability**: DNS/process-kill fault tests depend on OS signal semantics; results may
  vary on Windows targets.