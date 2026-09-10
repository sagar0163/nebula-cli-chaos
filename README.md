# nebula-cli-chaos

> Zero-infrastructure chaos & resilience testing for CLI applications.

[![CI](https://github.com/sagar0163/nebula-cli-chaos/workflows/CI/badge.svg)](https://github.com/sagar0163/nebula-cli-chaos/actions/workflows/ci.yml)
[![Release](https://github.com/sagar0163/nebula-cli-chaos/workflows/Release/badge.svg)](https://github.com/sagar0163/nebula-cli-chaos/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## What is this?

**nebula-cli-chaos is a chaos testing framework for CLI applications.** You point it at a
CLI command, it fires a battery of chaos tests at it (concurrency bursts, malformed input,
resource exhaustion, fault injection) and produces a pass/fail JSON report telling you where
that CLI breaks under pressure — all in pure Node.js, with no external infrastructure.

**Who it's for:** developers and maintainers who ship a CLI tool (Node, Python, Go, Rust, or
anything that runs as a subprocess) and want a quick, repeatable resilience check before
every release. If you already run Kubernetes +istio+Linkerd+Chaos Mesh and need kernel-level
network partitioning on live services, this is **not** that tool — see
[Comparison to other approaches](#comparison-to-other-approaches).

## The problem

CLIs fail in production the same way servers do: rate limits, malformed input, concurrent
bursts, DNS hiccups, memory pressure, being OOM-killed, or hanging forever. Most CLI projects
write zero resilience tests, so these failures surface at the worst possible moment — on a
customer machine.

## Current capabilities (v2.0.0)

The runner executes a **configurable suite of chaos tests** against a target command and
writes a machine-readable JSON report.

| Capability | Status |
|---|---|
| Concurrency / load tests (rapid-fire, 100x concurrent, zombie detection, fork-bomb input) | ✅ implemented |
| Fuzz tests (special chars, unicode, command injection, ReDoS, JSON bombs) | ✅ implemented |
| Memory / resource-exhaustion tests (1MB input, deep nesting) | ✅ implemented |
| Timeout & hang detection (slow-loris) | ✅ implemented |
| **Fault injection via pure Node.js** — network latency, DNS failure (direct + via subprocess), disk pressure, OOM kill, process kill | ✅ implemented (no root needed, no `tc netem`) |
| JSON report written to `chaos-report-<timestamp>.json` | ✅ implemented |
| Run against your own CLI by passing the command | ✅ implemented |
| YAML experiment definitions | ⏳ planned (config is JSON today) |
| `nebula-chaos report --format html` / `json` subcommand | ⏳ planned — prints "not implemented yet" and exits 0; reports are already written as JSON during a run |
| `nebula-chaos metrics` (Prometheus/HTTP) | ⏳ planned — prints "not implemented yet" |
| Kernel-level network faults (packet loss, bandwidth, `tc netem`) | ⏳ planned — requires an installed chaos-platform dependency |
| Automated recovery validation (checkpoint/restore, circuit-breaker checks) | ⏳ planned |

## Quick Start

The package is not published to npm yet, so install it from this repository.

```bash
# 1. Get the code and install dependencies
git clone https://github.com/sagar0163/nebula-cli-chaos.git
cd nebula-cli-chaos
npm install

# 2. Run the built-in test suite (25 chaos tests against the mock CLI fixture)
npm test
# ...or, without npm:
#   node chaos-runner.js

# 3. Run a single category
npm run test:fault-injection     # latency, DNS, disk pressure, OOM, process kill
node chaos-runner.js --category=network
node chaos-runner.js --category=fuzz

# 4. Chaos-test your own CLI
node chaos-runner.js path/to/your-cli
```

> The target must be an **executable path or command name** (no shell parsing — args are
> passed directly). The built-in suite was written against a standard CLI surface
> (`--help`, `--version`, `--input <text>`, `--path <path>`, `--stdin-input`), so point it at
> any CLI that supports those flags or extend `test-runner.js` / `chaos.config.json` with
> your own tests.

Each run produces a JSON report, e.g. `chaos-report-1789026291106.json`:

```json
{
  "timestamp": "2026-09-10T12:30:00.000Z",
  "command": "./fixtures/mock-cli.js",
  "summary": { "total": 25, "passed": 25, "failed": 0, "passRate": "100.0%", "durationMs": 1234 },
  "results": []
}
```

The runner exits nonzero if any test fails, so it drops straight into CI:

```yaml
# .github/workflows/ci.yml
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npm ci
- run: npm test
```

### Installing the `nebula` command globally (optional)

```bash
cd nebula-cli-chaos
npm install -g .
nebula --version        # 2.0.0
nebula                  # runs the full suite against chaos.config.json
nebula-chaos run        # same, via the run subcommand
nebula run my-config.json
```

## Configuration

Everything is driven by JSON config (`chaos.config.json` by default, override with
`--config=path.json`). The kingpin fields:

```jsonc
{
  "command": "./fixtures/mock-cli.js",   // target command to chaos-test
  "defaultTimeout": 10000,               // per-test timeout (ms)
  "reportDir": ".",                      // where chaos-report-*.json is written
  "categories": {                        // named lists of tests to run
    "network": [ "testConcurrency", "testSlowLoris" ],
    "fault-injection": [ "testFaultLatency", "testFaultDNSFailure" ]
  },
  "tests": {                             // per-test overrides
    "testConcurrency": { "category": "concurrency", "timeout": 15000 }
  }
}
```

Categories available out of the box: `network`, `memory`, `concurrency`, `fuzz`, `stress`,
`fault-injection`, and `all` (default).

## Fault types

Injected via pure Node.js `child_process` (no root, no `tc`, no toxiproxy):

| Fault | Test | Mechanism |
|---|---|---|
| Network latency | `testFaultLatency` | delayed subprocess exit |
| DNS failure | `testFaultDNSFailure` | unresolvable hostname (`dns.resolve4`) |
| DNS failure (via process) | `testFaultDNSFailureViaProcess` | same, through a spawned subprocess |
| Disk pressure | `testFaultDiskPressure` | writes a large temp file, then cleans up |
| OOM kill | `testFaultOOMKill` | child exceeds `--max-old-space-size` → killed |
| Process kill | `testFaultProcessKill` | SIGKILL after resource exhaustion |

## CLI reference

```
Usage:
  nebula-chaos run <config>      # run the full suite against a config file
  nebula-chaos report [options]  # not implemented yet
  nebula-chaos metrics [options] # not implemented yet
  nebula --help                  # this help
  nebula --version               # print version

Flags (any position):
  --category=<name>   run only tests in the named category (network|memory|concurrency|fuzz|stress|fault-injection|all)
  --config=<path>     JSON config file to use (default: chaos.config.json)
  <command>           ad-hoc target command to test (overrides config's "command")
```

## Comparison to other approaches

| | nebula-cli-chaos | Toxiproxy / Chaos Mesh |
|---|---|---|
| Target | any CLI **subprocess** | services on a network |
| Setup | `npm install`, zero infra | proxies, deployments, agents |
| Privileges | none (pure Node.js) | often root / cluster access |
| Faults | latency, DNS, disk, OOM, kill + input fuzzing | kernel-level packet manipulation |
| Best for | CLI developers who want fast pre-release resilience checks | platform engineers testing live microservices |

Use nebula-cli-chaos when your deliverable is a command-line tool; reach for an
infrastructure chaos platform when your deliverable is a distributed system.

## Roadmap

- YAML experiment definitions (`experiment: name / faults / assertions`)
- HTML report rendering + a working `nebula-chaos report --format <html|json>`
- Prometheus/HTTP metrics endpoint (`nebula-chaos metrics --port 9090`)
- Recovery validation (checkpoint/restore, idempotency, retry/circuit-breaker assertions)
- Programmatic API (`require('nebula-cli-chaos')`) in addition to the CLI

## License

MIT License

---

**Part of the [Nebula](https://github.com/sagar0163/Nebula_cli) ecosystem**