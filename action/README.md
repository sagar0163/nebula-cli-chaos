# Nebula CLI Chaos GitHub Action

Zero-config chaos testing for CLI applications in GitHub Actions. Run fault injection, resilience validation, and automated recovery tests with a single step.

## Features

- **Zero Configuration** - Just specify your CLI command and a profile
- **Cross-Platform** - Works on Ubuntu, macOS, and Windows runners
- **Multiple Profiles** - Pre-built chaos profiles for different scenarios
- **Rich Reports** - Markdown reports in GitHub Actions Summary and PR comments
- **No Root Required** - Uses only Node.js, no system-level fault injection

## Quick Start

```yaml
- uses: sagar0163/nebula-cli-chaos/action@main
  with:
    command: 'node my-cli.js'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `command` | Target CLI command to chaos-test | Yes | - |
| `profile` | Chaos profile: `standard`, `offline`, `disk-pressure`, `flaky-env` | No | `standard` |
| `config-path` | Path to custom `chaos.config.json` (overrides profile) | No | - |
| `timeout` | Default timeout for each test in milliseconds | No | `10000` |
| `fail-on-failure` | Fail the action if any chaos test fails | No | `true` |
| `post-comment` | Post results as PR comment (only on `pull_request` events) | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `report-json` | Path to the JSON report file |
| `summary` | Test summary (passed/failed/total) |
| `exit-code` | Exit code from chaos tests (0 = pass, 1 = fail) |

## Profiles

### `standard` (Default)
Runs all basic tests: help command, invalid args, concurrency, memory stress, fuzz tests, and more. Best for general CLI resilience testing.

### `offline`
Focuses on network-related resilience: latency injection, DNS failure simulation, slowloris attacks. Ideal for CLIs that make network requests.

### `disk-pressure`
Tests filesystem resilience: disk pressure simulation, large input handling, resource exhaustion. Perfect for CLIs that read/write files.

### `flaky-env`
Simulates unreliable environments: OOM kills, process signals, zombie detection. Great for testing error handling and recovery.

## Examples

### Basic Usage

```yaml
name: Chaos Testing
on: [push, pull_request]

jobs:
  chaos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - uses: sagar0163/nebula-cli-chaos/action@main
        with:
          command: 'node my-cli.js'
```

### Multiple Profiles

```yaml
name: Chaos Testing
on: [push, pull_request]

jobs:
  chaos-standard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sagar0163/nebula-cli-chaos/action@main
        with:
          command: 'node my-cli.js'
          profile: 'standard'

  chaos-offline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sagar0163/nebula-cli-chaos/action@main
        with:
          command: 'node my-cli.js'
          profile: 'offline'
```

### Custom Configuration

```yaml
- uses: sagar0163/nebula-cli-chaos/action@main
  with:
    command: 'python my-script.py'
    config-path: 'chaos.config.json'
    timeout: '30000'
```

### Matrix Strategy

```yaml
name: Chaos Testing
on: [push, pull_request]

jobs:
  chaos:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - uses: sagar0163/nebula-cli-chaos/action@main
        with:
          command: 'node my-cli.js'
```

## Reports

### GitHub Actions Summary
Results are automatically displayed in the GitHub Actions Summary tab with:
- Pass/fail status for each test
- Test duration and output
- Collapsible details for all results

### PR Comments
On `pull_request` events, a summary comment is posted with:
- Overall pass rate
- Failed test details
- Link to full report

### JSON Reports
A JSON report is generated for each run, containing:
- Full test results
- Timestamps and durations
- Error details

## How It Works

1. **Profile Selection** - Choose a pre-built chaos profile or provide custom config
2. **Config Generation** - Action generates `chaos.config.json` based on profile
3. **Test Execution** - Runs chaos tests against your CLI command
4. **Report Generation** - Creates Markdown and JSON reports
5. **Integration** - Posts to GitHub Summary and PR comments

## Requirements

- Node.js 20+ (for the action runtime)
- Your CLI command must be executable in the runner environment
- No root/sudo required

## License

MIT
