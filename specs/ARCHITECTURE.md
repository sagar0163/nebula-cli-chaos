# Architecture — nebula-cli-chaos

## Overview

nebula-cli-chaos runs a configurable battery of chaos tests against a target CLI command and
produces a JSON report. It is implemented in plain Node.js (CommonJS, no build step, no
runtime dependencies). The package exposes two sibling binary names, `nebula` and
`nebula-chaos`, both wired to the same entry point.

```
┌────────────────────────────┐
│  chaos-runner.js (bin)     │  CLI entry point: parse args → dispatch
└─────────────┬──────────────┘
              │  instantiates + drives
              ▼
┌────────────────────────────┐      reads          ┌──────────────────────────┐
│  ChaosTestRunner           │ ──────────────────▶ │  chaos.config.json        │
│  (test-runner.js)          │  target command,    │  command/categories/tests │
│  orchestration engine      │  categories, timeouts                    │
└───────┬────────────┬───────┘                     └──────────────────────────┘
        │            │
        │ spawns     │ uses for fault tests
        ▼            ▼
┌──────────────────────┐   ┌──────────────────────┐
│ target CLI           │   │ FaultInjector         │
│ (e.g. mock-cli.js)   │   │ (fault-injection.js)  │
│ + stdout/stderr/timing│  │ pure Node.js faults   │
└──────────────────────┘   └──────────────────────┘
        │
        ▼
┌────────────────────────────┐
│  generateReport()           │  writes chaos-report-<ts>.json
└────────────────────────────┘
```

## Component definitions

### 1. `chaos-runner.js` — CLI entry point

Zero-argument facade over `ChaosTestRunner`. Responsibilities:

- Print `--help` usage text and `--version`.
- Dispatch `nebula-chaos run <config>` → full-suite run against the given config file
  (defaults to `chaos.config.json`).
- Recognize `report` and `metrics` subcommands — **not implemented yet**, prints a stub
  message and exits 0.
- Otherwise pass arbitrary arguments (categories, `--config=`, or an ad-hoc target command)
  straight to the runner.

**Interface (CLI surface):**

```
nebula | nebula-chaos
  --help | -h
  --version | -v
  run <configPath>
  --category=<name>
  --config=<path>
  <targetCommand>          # ad-hoc override of config.command
```

### 2. `test-runner.js` — `ChaosTestRunner` (orchestration engine)

Core class. Owns the config, the target command, the result collection, and the report.

**Constructor** — `new ChaosTestRunner(configPath = 'chaos.config.json')`
Loads + validates config:
- `command` — target executable to chaos-test
- `defaultTimeout` — fallback per-test timeout (ms)
- `reportDir` — directory for the generated report
- `categories` — `{ name: [testMethodName, ...] }`
- `tests` — `{ testName: { category, timeout } }` per-test overrides

**`exec(args, options)`** — the one interface every test talks through.
Pipes to the target command, captures stdout/stderr/duration, and resolves:

```
Promise<{
  success: boolean,   // exit code === 0
  code: number,       // exit code, or -1 on spawn error / forced kill
  stdout: string,
  stderr: string,
  duration: number,   // ms
  timedOut: boolean,  // true when the timeout fired
  error?: string
}>
```

**Test methods** — each returns a normalized result object:
```
{ name: string, passed: boolean, output: string, error: string | null }
```
The suite is grouped into concerns:
- *Basic* — `testHelpCommand`, `testInvalidArgs`, `testEmptyInput`
- *Concurrency* — `testConcurrency`, `testRapidFire`, `testExtremeConcurrency`,
  `testZombieDetection`, `testForkBomb`
- *Memory/Stress* — `testLongInput`, `testMemoryStress`, `testJsonBomb`,
  `testResourceExhaustion`, `testDeepNesting`, `testSlowLoris`
- *Fuzz* — `testSpecialChars`, `testUnicode`, `testCommandInjection`, `testRedos`,
  `testAtomicBomb`
- *Fault injection* — `testFaultLatency`, `testFaultDNSFailure`,
  `testFaultDNSFailureViaProcess`, `testFaultDiskPressure`, `testFaultOOMKill`,
  `testFaultProcessKill`

**`runAll(category = 'all')`** — resolves the category against `config.categories`,
executes each test sequentially (name → method lookup, unknown names skipped), pushes results,
then reports. Returns the report object; the CLI exits `1` if `summary.failed > 0`.

**`generateReport()`** — writes `chaos-report-<epoch>.json` into `reportDir` and returns it.
`module.exports = ChaosTestRunner` (CLI + programmatic use).

### 3. `chaos.config.json` — shared configuration

Single source of truth. Schema:

```jsonc
{
  "command": "./fixtures/mock-cli.js",       // string — target executable
  "defaultTimeout": 10000,                   // number (ms)
  "reportDir": ".",                          // string — report output dir
  "categories": { "<name>": ["<testName>"] }, // map<string, string[]>
  "tests": { "<testName>": { "category": "x", "timeout": 5000 } }
}
```

### 4. `fault-injection.js` — `FaultInjector`

Stateless static-utility class. Pure Node.js only — no `tc`, no toxiproxy, no root. Each
method spawns an isolated `node` subprocess so faults never compromise the parent runner.

| Static method | Fault | Returns |
|---|---|---|
| `injectLatency(delayMs)` | network latency (delayed process) | `{ code, elapsed, injected }` |
| `simulateDNSFailure(hostname)` | DNS resolution failure | `{ failed, errorCode, hostname }` |
| `simulateDNSFailureViaProcess(hostname, timeoutMs)` | DNS failure in a subprocess | `{ failed, code, elapsed, hostname }` |
| `simulateDiskPressure({ bytes, tmpFile })` | disk write pressure (cleans up) | `{ code, requestedBytes, writtenBytes, success }` |
| `simulateOOMKill({ allocateMB, timeoutMs })` | memory exhaustion → OOM kill | `{ killed, code, elapsed, allocateMB }` |
| `simulateProcessKill(signal, timeoutMs)` | signal-kill a busy process | `{ killed, signal, code, elapsed }` |

### 5. `fixtures/mock-cli.js` — self-test target

A deliberately hardened mini-CLI that the default config points at, so `npm test` exercises
the full engine without external dependencies. Handles `--help`, `--version`,
`--input <text>`, `--path <path>`, `--query/--search <text>`, `--stdin-input`; rejects
unsafe/oversized input with exit code 1.

## Data flows

**Cold start → report:**

1. `npm test` → `node chaos-runner.js` (no args) → `runTests(args)`.
2. Fill defaults: `category='all'`, `configPath='chaos.config.json'`, no command override.
3. `new ChaosTestRunner(configPath)` loads config (`command`, `defaultTimeout`,
   `categories`, `tests`).
4. `runAll('all')`: for each test name in `categories['all']`, look up the method on the
   instance, `await` it, append its `{ name, passed, output, error }` to `results`.
5. Test methods call `exec(...)` (spawn target + capture) or `FaultInjector.*`
   (fault tests) and derive a pass/fail from the returned data.
6. `generateReport()` evaluates `{ summary, results }`, writes
   `chaos-report-<Date.now()>.json` to `reportDir`, prints it.
7. `chaos-runner.js` maps `summary.failed > 0` → exit code 1, else 0. (CI relies on this.)

**Category filter:** `node chaos-runner.js --category=network` short-circuits the same flow at
step 4 with `categories['network']`.

**Ad-hoc target:** `node chaos-runner.js ./fixtures/mock-cli.js` sets `runner.command` before
step 4, so the whole suite hits a different binary without editing config.

**Programmatic use:** `require('./test-runner')` and `new ChaosTestRunner(...).runAll(...)`
is contract-identical to the CLI path.

## Extension points

- **Add a test**: define `async testMyFault()` in `test-runner.js`, register it under a
  category in `chaos.config.json`, optionally pin a timeout in `tests`.
- **Test a new target**: either pass the command at the CLI, or change `chaos.config.json`
  `command` (works best with the standard flag surface; see README).
- **New fault**: add a `FaultInjector` static and a matching `testFault*` test that asserts on
  its return shape.

## Known limitations

- `report` and `metrics` subcommands are stubs (exit 0, "not implemented yet").
- The runner is single-file, sequential per category; no parallelism across tests.
- No YAML experiment language; configuration is JSON.
- Fault injection is process-level simulation, not kernel-level packet surgery.