# nebula-cli-chaos

> **Chaos testing framework for CLI applications — fault injection, resilience validation, automated recovery**

[![CI](https://github.com/sagar0163/nebula-cli-chaos/workflows/CI/badge.svg)](https://github.com/sagar0163/nebula-cli-chaos/actions/workflows/ci.yml)
[![Release](https://github.com/sagar0163/nebula-cli-chaos/workflows/Release/badge.svg)](https://github.com/sagar0163/nebula-cli-chaos/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Problem

CLI tools fail in production due to network partitions, disk full, permission errors, rate limits, and dependency failures. Most CLI projects have zero resilience testing.

## 💡 Solution

A **programmatic chaos engineering framework** for CLI applications:

- **Fault injection** — network latency, packet loss, DNS failures, disk pressure, OOM kills
- **Resilience validation** — automated retry, circuit breaker, fallback verification
- **Recovery testing** — state reconstruction, checkpoint/restore, idempotency checks
- **CLI-native** — works with any CLI tool (Node, Python, Go, Rust, bash)

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Chaos Controller                          │
├─────────────────┬─────────────────┬──────────────────────────┤
│  Fault          │  Observer       │  Reporter                │
│  Injector       │  (metrics/      │  (HTML/JSON/             │
│  (network,      │   logs/traces)  │   Prometheus)            │
│   disk, CPU)    │                 │                          │
└─────────────────┴─────────────────┴──────────────────────────┘
```

## 🚀 Quick Start

```bash
# Install
npm install -g @nebula/chaos

# Define chaos experiment
cat > chaos-experiment.yaml <<'EOF'
experiment:
  name: "network-partition-test"
  target: "my-cli-tool"
  faults:
    - type: "network-latency"
      latency: "500ms"
      jitter: "100ms"
      duration: "30s"
    - type: "dns-failure"
      probability: 0.3
  assertions:
    - "exit_code != 0"
    - "retries <= 3"
    - "fallback_triggered == true"
EOF

# Run experiment
nebula-chaos run chaos-experiment.yaml
```

## 🔧 Configuration

```yaml
# .nebula-chaos/config.yaml
chaos:
  defaultTimeout: "5m"
  maxConcurrentExperiments: 3
  safety:
    killSwitch: true
    maxFaultDuration: "10m"

faults:
  network:
    latency:
      min: "10ms"
      max: "2000ms"
    packetLoss:
      min: 0.01
      max: 0.5
    bandwidth:
      min: "10kbps"
      max: "100Mbps"
  disk:
    fill:
      minPercent: 80
      maxPercent: 99
    ioError:
      probability: 0.1
  process:
    oomKill: true
    cpuThrottle:
      minPercent: 10
      maxPercent: 90
```

## 📊 Fault Types

| Category | Faults |
|---|---|
| **Network** | latency, packet loss, bandwidth limit, DNS failure, connection reset, TLS error |
| **Disk** | fill, IO error, permission denied, readonly, corruption |
| **Process** | OOM kill, CPU throttle, signal (SIGTERM, SIGKILL), zombie |
| **Stream/IO** | pipe break (SIGPIPE), stdin random bytes, stdin EOF injection, stdout throttle, stderr throttle |
| **Dependency** | API rate limit, service unavailable, timeout, malformed response |
| **Time** | clock skew, NTP drift, leap second |

## 🔌 Standard Stream Fault Injection

CLI tools rely on stdin/stdout/stderr and pipe chains. These faults test how your CLI handles broken pipes, garbage input, and blocked IO.

### YAML Experiment Examples

```yaml
# Pipe Break (SIGPIPE) - simulate downstream consumer dying
experiment:
  name: "pipe-break-test"
  target: "my-cli-tool"
  faults:
    - type: "pipe-break"
      pipeDuration: 100        # ms before pipe is destroyed
      writeData: "AAAAAAAAAA"   # data to write before break
  assertions:
    - "exit_code == 141"        # SIGPIPE exit code
```

```yaml
# Stdin Random Bytes - inject garbage data into standard input
experiment:
  name: "stdin-fuzz-test"
  target: "my-cli-tool"
  faults:
    - type: "stdin-random-bytes"
      dataLength: 50            # number of random bytes to inject
      eofChance: 0.5            # probability of injecting EOF (0.0-1.0)
  assertions:
    - "exit_code != 0"
    - "stderr contains 'invalid'"
```

```yaml
# Stdin EOF - close stdin immediately
experiment:
  name: "stdin-eof-test"
  target: "my-cli-tool"
  faults:
    - type: "stdin-eof"
  assertions:
    - "exit_code == 0 || exit_code == 1"
```

```yaml
# Stdout Throttle - block stdout buffer to test for hangs
experiment:
  name: "stdout-throttle-test"
  target: "my-cli-tool"
  faults:
    - type: "stdout-throttle"
      holdTime: 500             # ms to hold stdout buffer
      writeData: "BBBBBBBBBB"
  assertions:
    - "hang_detected == false"
    - "exit_code == 0"
```

```yaml
# Stderr Throttle - block stderr buffer
experiment:
  name: "stderr-throttle-test"
  target: "my-cli-tool"
  faults:
    - type: "stderr-throttle"
      holdTime: 500
      writeData: "CCCCCCCCCC"
  assertions:
    - "exit_code == 0"
```

### Running Stream Fault Tests

```bash
# Run all stream/pipe fault tests
nebula --category=fault-injection

# Run from chaos.config.json
nebula-chaos run chaos.config.json
```

## 📈 Reporting

```bash
# HTML report
nebula-chaos report --format html --output report.html

# JSON for CI integration
nebula-chaos report --format json --output report.json

# Prometheus metrics
nebula-chaos metrics --port 9090
```

## 🤖 CI Integration

```yaml
# .github/workflows/chaos.yml
name: Chaos Testing
on: [push, pull_request]
jobs:
  chaos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - run: npx nebula-chaos run experiments/*.yaml --ci
```

## 🚀 GitHub Action (Zero-Config)

Use the official GitHub Action for instant chaos testing in your CI pipeline:

```yaml
# .github/workflows/chaos.yml
name: Chaos Testing
on: [push, pull_request]

jobs:
  chaos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sagar0163/nebula-cli-chaos/action@main
        with:
          command: 'node my-cli.js'
          profile: 'standard'
```

### Available Profiles

| Profile | Description |
|---------|-------------|
| `standard` | All basic tests (help, args, concurrency, memory, fuzz) |
| `offline` | Network resilience (latency, DNS failure, slowloris) |
| `disk-pressure` | Filesystem resilience (disk full, large inputs) |
| `flaky-env` | Unreliable environment (OOM, process signals, zombies) |

### Features

- **Zero Configuration** - Just specify your command and profile
- **Cross-Platform** - Works on Ubuntu, macOS, and Windows
- **Rich Reports** - Markdown reports in GitHub Actions Summary and PR comments
- **No Root Required** - Uses only Node.js

See [action/README.md](action/README.md) for full documentation and [examples/chaos-action.yml](examples/chaos-action.yml) for complete workflow examples.

## 📄 License

MIT License

---

**Part of the [Nebula](https://github.com/sagar0163/Nebula_cli) ecosystem**