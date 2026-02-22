# Nebula-CLI Chaos Testing Framework

Comprehensive chaos and stress testing for CLI applications.

## Features

- Network failure simulation
- Memory stress testing
- Concurrent execution testing
- Invalid input fuzzing
- Timeout and hang detection
- Resource exhaustion simulation

## Installation

```bash
npm install
```

## Running Tests

```bash
# Run all chaos tests
npm test

# Run specific test category
npm run test:network
npm run test:memory
npm run test:concurrency
npm run test:fuzz

# Run with coverage
npm run test:coverage
```

## Test Categories

### 1. Network Chaos
- Latency injection
- Packet loss simulation
- DNS failure
- Connection timeout
- SSL certificate errors

### 2. Memory Chaos
- Memory exhaustion
- Memory leak detection
- Heap limit testing

### 3. Concurrency Chaos
- Race condition detection
- Concurrent request storms
- Parallel execution

### 4. Input Chaos
- Invalid arguments
- Malformed JSON
- Empty inputs
- Unicode injection
- Command injection attempts

### 5. Timeout Chaos
- Long-running commands
- Stuck process detection
- Graceful timeout handling

## Usage in Code

```javascript
const { ChaosMonkey } = require('./chaos-monkey');

const chaos = new ChaosMonkey({
  enableNetworkChaos: true,
  enableMemoryChaos: true,
  enableConcurrencyChaos: true
});

// Wrap your CLI command
const result = await chaos.run('nebula-cli --help');
```

## Test Results

Tests output:
- JSON format for CI/CD integration
- HTML report for human review
- JUnit XML for CI systems
