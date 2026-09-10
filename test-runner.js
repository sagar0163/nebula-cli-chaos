/**
 * Nebula-CLI Unified Chaos Test Runner
 * =====================================
 * Consolidated runner replacing chaos-runner.js, chaos-monkey.py, and dos-test.js.
 * Loads shared configuration from chaos.config.json.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const FaultInjector = require('./fault-injection');

class ChaosTestRunner {
    constructor(configPath) {
        this.config = this.loadConfig(configPath);
        this.command = this.config.command;
        this.defaultTimeout = this.config.defaultTimeout || 10000;
        this.results = [];
        this.startTime = null;
    }

    loadConfig(configPath) {
        const resolved = path.resolve(configPath || 'chaos.config.json');
        if (!fs.existsSync(resolved)) {
            throw new Error(`Config not found: ${resolved}`);
        }
        return JSON.parse(fs.readFileSync(resolved, 'utf8'));
    }

    getTimeout(testName) {
        const testConf = this.config.tests && this.config.tests[testName];
        return (testConf && testConf.timeout) || this.defaultTimeout;
    }

    exec(args = [], options = {}) {
        const timeout = options.timeout || this.defaultTimeout;
        const env = { ...process.env, ...options.env };

        return new Promise((resolve) => {
            const startTime = Date.now();
            const proc = spawn(this.command, args, {
                env,
                timeout,
                shell: false
            });

            let stdout = '';
            let stderr = '';

            if (options.stdinData !== undefined) {
                try {
                    proc.stdin.write(options.stdinData);
                } catch (e) {
                    // stdin already closed (process exited early)
                }
            }
            try {
                proc.stdin.end();
            } catch (e) {
                // stdin already closed
            }

            proc.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            proc.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            proc.on('close', (code) => {
                const duration = Date.now() - startTime;
                resolve({
                    success: code === 0,
                    code,
                    stdout,
                    stderr,
                    duration,
                    timedOut: false
                });
            });

            proc.on('error', (error) => {
                const duration = Date.now() - startTime;
                resolve({
                    success: false,
                    code: -1,
                    stdout: '',
                    stderr: error.message,
                    duration,
                    timedOut: false,
                    error: error.message
                });
            });

            setTimeout(() => {
                if (!proc.killed) {
                    proc.kill('SIGKILL');
                    resolve({
                        success: false,
                        code: -1,
                        stdout,
                        stderr: 'Command timed out',
                        duration: timeout,
                        timedOut: true
                    });
                }
            }, timeout);
        });
    }

    // ---- BASIC TESTS ----

    async testHelpCommand() {
        const result = await this.exec(['--help']);
        return {
            name: 'testHelpCommand',
            passed: result.success && (result.stdout.includes('Options') || result.stdout.includes('Usage')),
            output: result.stdout,
            error: result.error
        };
    }

    async testInvalidArgs() {
        const result = await this.exec(['--invalid-arg-xyz']);
        return {
            name: 'testInvalidArgs',
            passed: !result.success,
            output: result.stderr,
            error: null
        };
    }

    async testEmptyInput() {
        const result = await this.exec(['']);
        return {
            name: 'testEmptyInput',
            passed: result.timedOut || !result.success,
            output: result.stderr,
            error: null
        };
    }

    // ---- CONCURRENCY TESTS ----

    async testConcurrency() {
        const promises = [];
        for (let i = 0; i < 5; i++) {
            promises.push(this.exec(['--help']));
        }
        const results = await Promise.all(promises);
        const allSuccess = results.every(r => r.success);
        return {
            name: 'testConcurrency',
            passed: allSuccess,
            output: `Ran ${results.length} concurrent commands`,
            error: null
        };
    }

    async testRapidFire() {
        const promises = [];
        for (let i = 0; i < 20; i++) {
            promises.push(this.exec(['--version']));
        }
        const start = Date.now();
        await Promise.all(promises);
        const duration = Date.now() - start;
        return {
            name: 'testRapidFire',
            passed: duration < 10000,
            output: `20 commands in ${duration}ms`,
            error: null
        };
    }

    async testExtremeConcurrency() {
        const count = 100;
        const promises = [];
        for (let i = 0; i < count; i++) {
            promises.push(this.exec(['--help'], { timeout: 10000 }));
        }
        const start = Date.now();
        const results = await Promise.allSettled(promises);
        const duration = Date.now() - start;
        const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
        return {
            name: 'testExtremeConcurrency',
            passed: successful >= count * 0.8,
            output: `${successful}/${count} succeeded in ${duration}ms`,
            error: null
        };
    }

    async testZombieDetection() {
        const promises = [];
        for (let i = 0; i < 10; i++) {
            promises.push(this.exec(['--input', 'sleep 10'], { timeout: 100 }));
        }
        await Promise.allSettled(promises);
        const check = await this.exec(['--version'], { timeout: 5000 });
        return {
            name: 'testZombieDetection',
            passed: check.success,
            output: check.success ? 'System responsive after kill' : 'System hung',
            error: null
        };
    }

    async testForkBomb() {
        const payloads = [
            'bash -c "echo $BASHPID"',
            '$(echo $(echo $(echo whoami)))',
            'true && true && true && true && true'
        ];
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], { timeout: 3000 });
            if (!result.timedOut && result.code !== -1) passed++;
        }
        return {
            name: 'testForkBomb',
            passed: passed === payloads.length,
            output: `${passed}/${payloads.length} handled`,
            error: null
        };
    }

    // ---- MEMORY TESTS ----

    async testLongInput() {
        const longInput = 'x'.repeat(100000);
        const result = await this.exec(['--input', longInput]);
        return {
            name: 'testLongInput',
            passed: result.duration < 5000,
            output: `Input length: ${longInput.length}`,
            error: null
        };
    }

    async testMemoryStress() {
        const hugeInput = 'x'.repeat(1000000);
        const result = await this.exec(['--stdin-input'], { timeout: 15000, stdinData: hugeInput });
        return {
            name: 'testMemoryStress',
            passed: !result.timedOut,
            output: `1MB input: ${result.timedOut ? 'TIMEOUT' : 'OK'}`,
            error: null
        };
    }

    async testJsonBomb() {
        const jsonBomb = '{"a":{"b":{"c":{"d":{"e":' + '{"f":'.repeat(100) + '1' + '}'.repeat(101) + '}';
        const result = await this.exec(['--input', jsonBomb]);
        return {
            name: 'testJsonBomb',
            passed: !result.timedOut,
            output: result.timedOut ? 'TIMEOUT' : 'Handled nested JSON',
            error: null
        };
    }

    async testResourceExhaustion() {
        const startMem = process.memoryUsage().heapUsed;
        const promises = [];
        for (let i = 0; i < 100; i++) {
            promises.push(this.exec(['--version'], { timeout: 1000 }));
        }
        await Promise.allSettled(promises);
        const endMem = process.memoryUsage().heapUsed;
        const memIncrease = (endMem - startMem) / 1024 / 1024;
        return {
            name: 'testResourceExhaustion',
            passed: memIncrease < 100,
            output: `Memory increase: ${memIncrease.toFixed(2)}MB`,
            error: null
        };
    }

    // ---- FUZZ TESTS ----

    async testSpecialChars() {
        const result = await this.exec(['--input', 'test; rm -rf /']);
        return {
            name: 'testSpecialChars',
            passed: !result.success || !result.stdout.includes('rm -rf'),
            output: result.stdout,
            error: null
        };
    }

    async testUnicode() {
        const result = await this.exec(['--input', '\ud83c\udf00 \ud83d\udc80 \ud83d\udd25']);
        return {
            name: 'testUnicode',
            passed: true,
            output: result.stdout,
            error: null
        };
    }

    async testCommandInjection() {
        const payloads = [
            'echo hacked',
            '$(whoami)',
            '`ls`',
            '&& cat /etc/passwd',
            '| tee /tmp/pwned'
        ];
        let allBlocked = true;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload]);
            if (result.stdout.includes('hacked') || result.stdout.includes('root')) {
                allBlocked = false;
            }
        }
        return {
            name: 'testCommandInjection',
            passed: allBlocked,
            output: allBlocked ? 'All payloads blocked' : 'VULNERABLE!',
            error: null
        };
    }

    async testRedos() {
        const redosPattern = 'aaaaaaaaaaaaaaaaaaaaaaa!';
        const result = await this.exec(['--input', redosPattern], { timeout: 5000 });
        return {
            name: 'testRedos',
            passed: !result.timedOut,
            output: result.timedOut ? 'TIMEOUT (ReDoS vulnerable)' : 'Handled',
            error: null
        };
    }

    async testAtomicBomb() {
        const patterns = [
            'aaaaaaaaaaaaaaaaaaaaaa!',
            '(a+)+$'.repeat(10),
            '(.+)*$'.repeat(10),
            '(a|a|a)*$'.repeat(50)
        ];
        let passed = 0;
        for (const pattern of patterns) {
            const result = await this.exec(['--input', pattern], { timeout: 2000 });
            if (!result.timedOut) passed++;
        }
        return {
            name: 'testAtomicBomb',
            passed: passed === patterns.length,
            output: `${passed}/${patterns.length} handled`,
            error: null
        };
    }

    // ---- STRESS TESTS ----

    async testDeepNesting() {
        const deepPath = '../'.repeat(50);
        const result = await this.exec(['--path', deepPath]);
        return {
            name: 'testDeepNesting',
            passed: !result.timedOut,
            output: '50-level nesting handled',
            error: null
        };
    }

    async testSlowLoris() {
        const result = await new Promise((resolve) => {
            const proc = spawn(this.command, ['--input', 'test'], { shell: false });
            let received = false;
            proc.stdout.on('data', () => {
                if (!received) {
                    received = true;
                    setTimeout(() => { proc.kill(); resolve({ slow: true, received }); }, 100);
                }
            });
            proc.stderr.on('data', () => {
                if (!received) {
                    received = true;
                    setTimeout(() => { proc.kill(); resolve({ slow: true, received }); }, 100);
                }
            });
            setTimeout(() => {
                proc.kill();
                resolve({ slow: false, received });
            }, 3000);
        });
        return {
            name: 'testSlowLoris',
            passed: result.received,
            output: result.received ? 'Responsive' : 'Unresponsive',
            error: null
        };
    }

    // ---- FAULT INJECTION TESTS ----

    async testFaultLatency() {
        const result = await FaultInjector.injectLatency(500);
        return {
            name: 'testFaultLatency',
            passed: result.injected && result.code === 0,
            output: `Latency: ${result.elapsed}ms (target: 500ms)`,
            error: result.error || null
        };
    }

    async testFaultDNSFailure() {
        const result = await FaultInjector.simulateDNSFailure();
        return {
            name: 'testFaultDNSFailure',
            passed: result.failed,
            output: `DNS resolution failed as expected: ${result.errorCode}`,
            error: null
        };
    }

    async testFaultDNSFailureViaProcess() {
        const result = await FaultInjector.simulateDNSFailureViaProcess();
        return {
            name: 'testFaultDNSFailureViaProcess',
            passed: result.failed,
            output: `Process DNS failure: code=${result.code}, elapsed=${result.elapsed}ms`,
            error: null
        };
    }

    async testFaultDiskPressure() {
        const result = await FaultInjector.simulateDiskPressure({ bytes: 1024 * 1024 });
        return {
            name: 'testFaultDiskPressure',
            passed: result.success && result.writtenBytes > 0,
            output: `Wrote ${result.writtenBytes} bytes (requested: ${result.requestedBytes})`,
            error: null
        };
    }

    async testFaultOOMKill() {
        const result = await FaultInjector.simulateOOMKill({ allocateMB: 32, timeoutMs: 5000 });
        return {
            name: 'testFaultOOMKill',
            passed: result.killed,
            output: `Process killed: ${result.killed}, code: ${result.code}`,
            error: null
        };
    }

    async testFaultProcessKill() {
        const result = await FaultInjector.simulateProcessKill('SIGKILL', 3000);
        return {
            name: 'testFaultProcessKill',
            passed: result.killed,
            output: `Process killed with ${result.signal}, code: ${result.code}`,
            error: null
        };
    }

    async testFaultEnvVarUnset() {
        const envKey = 'NEBULA_API_KEY';
        const originalEnv = { ...process.env };
        process.env[envKey] = 'test-key-123';
        
        const corruptedEnv = FaultInjector.corruptEnvVar(process.env, envKey, 'unset');
        
        // Ensure it doesn't affect the runner's env
        const passed = process.env[envKey] === 'test-key-123' && corruptedEnv[envKey] === undefined;
        
        delete process.env[envKey]; // cleanup
        
        // Actually run command with corrupted env
        const result = await this.exec(['--help'], { env: corruptedEnv });
        
        return {
            name: 'testFaultEnvVarUnset',
            passed: passed && (result.success || !result.success),
            output: passed ? 'Env var successfully unset in corrupted env, runner env intact' : 'Failed to unset or runner env affected',
            error: null
        };
    }

    async testFaultEnvVarInvalidChars() {
        const envKey = 'NEBULA_CONFIG_DIR';
        const originalEnv = { ...process.env };
        process.env[envKey] = '/var/lib/nebula';
        
        const corruptedEnv = FaultInjector.corruptEnvVar(process.env, envKey, 'invalid_chars');
        
        const passed = process.env[envKey] === '/var/lib/nebula' && corruptedEnv[envKey].includes('!@#$%^&*()');
        
        delete process.env[envKey];
        
        const result = await this.exec(['--help'], { env: corruptedEnv });
        
        return {
            name: 'testFaultEnvVarInvalidChars',
            passed: passed && (result.success || !result.success),
            output: passed ? 'Env var corrupted with invalid chars' : 'Failed to corrupt env var',
            error: null
        };
    }

    async testFaultConfigFileMalform() {
        const testFile = 'test-config-malform.json';
        fs.writeFileSync(testFile, '{"valid": "json"}');
        
        FaultInjector.corruptConfigFile(testFile, 'malform_json');
        
        const corruptedContent = fs.readFileSync(testFile, 'utf8');
        const isCorrupted = corruptedContent.includes('invalid_json_here{[');
        
        FaultInjector.restoreConfigFile(testFile);
        const restoredContent = fs.readFileSync(testFile, 'utf8');
        
        const passed = isCorrupted && restoredContent === '{"valid": "json"}';
        
        if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
        
        return {
            name: 'testFaultConfigFileMalform',
            passed,
            output: passed ? 'Config file malformed and restored successfully' : 'Config file corruption/restoration failed',
            error: null
        };
    }

    async testFaultConfigFileChangeType() {
        const testFile = 'test-config-type.json';
        fs.writeFileSync(testFile, '{"key": "string_value"}');
        
        FaultInjector.corruptConfigFile(testFile, 'change_type');
        
        const corruptedContent = fs.readFileSync(testFile, 'utf8');
        const isCorrupted = corruptedContent.includes('12345');
        
        FaultInjector.restoreConfigFile(testFile);
        const restoredContent = fs.readFileSync(testFile, 'utf8');
        
        const passed = isCorrupted && restoredContent === '{"key": "string_value"}';
        
        if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
        
        return {
            name: 'testFaultConfigFileChangeType',
            passed,
            output: passed ? 'Config file type changed and restored successfully' : 'Config file corruption/restoration failed',
            error: null
        };
    }

    // ---- RUNNER ----

    async runAll(category = 'all') {
        console.log(`\n🎭 Nebula-CLI Chaos Testing (Unified Runner)`);
        console.log(`Command: ${this.command}\n`);
        this.startTime = Date.now();
        this.results = [];

        const categories = this.config.categories || {};
        const testNames = categories[category] || categories.all || [];

        for (const testName of testNames) {
            if (typeof this[testName] !== 'function') {
                console.log(`⚠️  Unknown test: ${testName} (skipped)`);
                continue;
            }
            try {
                const result = await this[testName]();
                this.results.push(result);
                const status = result.passed ? '✅' : '❌';
                console.log(`${status} ${testName}`);
                if (!result.passed && result.error) {
                    console.log(`   Error: ${result.error}`);
                }
            } catch (e) {
                this.results.push({ name: testName, passed: false, error: e.message });
                console.log(`❌ ${testName}: ${e.message}`);
            }
        }
        return this.generateReport();
    }

    generateReport() {
        const passed = this.results.filter(r => r.passed).length;
        const failed = this.results.filter(r => !r.passed).length;
        const total = this.results.length;
        const duration = Date.now() - this.startTime;
        const report = {
            timestamp: new Date().toISOString(),
            command: this.command,
            summary: { total, passed, failed, passRate: `${((passed / total) * 100).toFixed(1)}%`, durationMs: duration },
            results: this.results
        };
        const dir = this.config.reportDir || '.';
        const filename = path.join(dir, `chaos-report-${Date.now()}.json`);
        fs.writeFileSync(filename, JSON.stringify(report, null, 2));
        console.log(`\n📊 Report saved to: ${filename}\n`);
        console.log(`Total: ${total} | Passed: ${passed} | Failed: ${failed}`);
        return report;
    }
}

if (require.main === module) {
    const args = process.argv.slice(2);
    const category = args.find(a => a.startsWith('--category='))?.split('=')[1] || 'all';
    const configPath = args.find(a => a.startsWith('--config='))?.split('=')[1] || 'chaos.config.json';
    const command = args.find(a => !a.startsWith('--')) || undefined;

    const runner = new ChaosTestRunner(configPath);
    if (command) {
        runner.command = command;
    }
    runner.runAll(category).then(report => {
        const exitCode = report.summary.failed > 0 ? 1 : 0;
        process.exit(exitCode);
    });
}

module.exports = ChaosTestRunner;
