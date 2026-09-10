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

**No root required.** All fault injection runs entirely in user space using standard POSIX and Node.js mechanisms — no eBPF, no kernel modules, no `sudo`, no `tc netem`.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          nebula-chaos CLI                                   │
├─────────────────┬──────────────────────────┬────────────────────────────────┤
│  Fault          │  Process Spawning        │  Filesystem Interception       │
│  Injector       │  (child_process.spawn)   │  (LD_PRELOAD / fs_injector.so) │
│  (latency,      │  controlled env, stdin,  │  intercepts open(), write()    │
│   DNS, OOM,     │  timeout, signals        │  returns EACCES / ENOSPC       │
│   disk, kill)   │                          │                                │
└─────────────────┴──────────────────────────┴────────────────────────────────┘
```

**How it works:**

| Mechanism | What It Intercepts | Root Required? |
|---|---|---|
| `child_process` spawning | Network latency, DNS, process lifecycle | No |
| `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` | Filesystem syscalls (`open`, `write`) | No |
| Environment variable pass-through | Injection configuration | No |
| DNS poison via `.invalid` TLD | DNS resolution | No |

> **For the full architectural breakdown** — cross-platform details, the `LD_PRELOAD` mechanism explained, security considerations, and component diagrams — see [`specs/ARCHITECTURE.md`](specs/ARCHITECTURE.md).

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
| **Dependency** | API rate limit, service unavailable, timeout, malformed response |
| **Time** | clock skew, NTP drift, leap second |

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

## 📄 License

MIT License

---

**Part of the [Nebula](https://github.com/sagar0163/Nebula_cli) ecosystem**