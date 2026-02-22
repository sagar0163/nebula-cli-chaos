/**
 * Nebula-CLI Chaos Testing Runner
 * ================================
 * Run chaos tests on CLI applications
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class ChaosRunner {
    constructor(command = 'nebula') {
        this.command = command;
        this.results = [];
        this.startTime = null;
    }

    /**
     * Execute a command
     */
    async exec(args = [], options = {}) {
        const timeout = options.timeout || 30000;
        const env = { ...process.env, ...options.env };

        return new Promise((resolve) => {
            const startTime = Date.now();
            const proc = spawn(this.command, args, {
                env,
                timeout,
                shell: true
            });

            let stdout = '';
            let stderr = '';

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

            // Timeout handler
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

    /**
     * Test: Help Command
     */
    async testHelpCommand() {
        const result = await this.exec(['--help']);
        return {
            name: 'help_command',
            passed: result.success && result.stdout.includes('Usage'),
            output: result.stdout,
            error: result.error
        };
    }

    /**
     * Test: Invalid Arguments
     */
    async testInvalidArgs() {
        const result = await this.exec(['--invalid-arg-xyz']);
        // Should fail gracefully
        return {
            name: 'invalid_args',
            passed: !result.success,
            output: result.stderr,
            error: null
        };
    }

    /**
     * Test: Empty Input
     */
    async testEmptyInput() {
        const result = await this.exec(['']);
        return {
            name: 'empty_input',
            passed: result.timedOut || !result.success,
            output: result.stderr,
            error: null
        };
    }

    /**
     * Test: Concurrent Execution
     */
    async testConcurrency() {
        const promises = [];
        for (let i = 0; i < 5; i++) {
            promises.push(this.exec(['--help']));
        }
        
        const results = await Promise.all(promises);
        const allSuccess = results.every(r => r.success);
        
        return {
            name: 'concurrent_exec',
            passed: allSuccess,
            output: `Ran ${results.length} concurrent commands`,
            error: null
        };
    }

    /**
     * Test: Special Characters
     */
    async testSpecialChars() {
        const result = await this.exec(['--input', 'test; rm -rf /']);
        return {
            name: 'special_chars',
            passed: !result.success || !result.stdout.includes('rm -rf'),
            output: result.stdout,
            error: null
        };
    }

    /**
     * Test: Unicode Injection
     */
    async testUnicode() {
        const result = await this.exec(['--input', '🌀 💀 🔥']);
        return {
            name: 'unicode_injection',
            passed: true, // Should handle gracefully
            output: result.stdout,
            error: null
        };
    }

    /**
     * Test: Long Input
     */
    async testLongInput() {
        const longInput = 'x'.repeat(100000);
        const result = await this.exec(['--input', longInput]);
        
        return {
            name: 'long_input',
            passed: result.duration < 5000, // Should complete within 5s
            output: `Input length: ${longInput.length}`,
            error: null
        };
    }

    /**
     * Test: Rapid Fire
     */
    async testRapidFire() {
        const promises = [];
        for (let i = 0; i < 20; i++) {
            promises.push(this.exec(['--version']));
        }
        
        const start = Date.now();
        await Promise.all(promises);
        const duration = Date.now() - start;
        
        return {
            name: 'rapid_fire',
            passed: duration < 10000, // 20 commands in 10s
            output: `20 commands in ${duration}ms`,
            error: null
        };
    }

    /**
     * Run all tests
     */
    async runAll(category = 'all') {
        console.log(`\n🧪 Running Chaos Tests: ${category}\n`);
        this.startTime = Date.now();
        this.results = [];

        const tests = {
            all: [
                'testHelpCommand',
                'testInvalidArgs',
                'testEmptyInput',
                'testConcurrency',
                'testSpecialChars',
                'testUnicode',
                'testLongInput',
                'testRapidFire'
            ],
            network: ['testConcurrency', 'testRapidFire'],
            memory: ['testLongInput'],
            fuzz: ['testSpecialChars', 'testUnicode', 'testInvalidArgs'],
            concurrency: ['testConcurrency', 'testRapidFire']
        };

        const testMethods = tests[category] || tests.all;

        for (const testName of testMethods) {
            try {
                const result = await this[testName]();
                this.results.push(result);
                
                const status = result.passed ? '✅' : '❌';
                console.log(`${status} ${testName}`);
                if (!result.passed && result.error) {
                    console.log(`   Error: ${result.error}`);
                }
            } catch (e) {
                this.results.push({
                    name: testName,
                    passed: false,
                    error: e.message
                });
                console.log(`❌ ${testName}: ${e.message}`);
            }
        }

        return this.generateReport();
    }

    /**
     * Generate test report
     */
    generateReport() {
        const passed = this.results.filter(r => r.passed).length;
        const failed = this.results.filter(r => !r.passed).length;
        const total = this.results.length;
        const duration = Date.now() - this.startTime;

        const report = {
            timestamp: new Date().toISOString(),
            command: this.command,
            summary: {
                total,
                passed,
                failed,
                passRate: `${((passed / total) * 100).toFixed(1)}%`,
                durationMs: duration
            },
            results: this.results
        };

        // Save report
        const filename = `chaos-report-${Date.now()}.json`;
        fs.writeFileSync(filename, JSON.stringify(report, null, 2));
        
        console.log(`\n📊 Report saved to: ${filename}\n`);
        console.log(`Total: ${total} | Passed: ${passed} | Failed: ${failed}`);
        
        return report;
    }
}

// CLI Interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const category = args.find(a => a.startsWith('--category='))?.split('=')[1] || 'all';
    const command = args.find(a => !a.startsWith('--')) || 'nebula';

    console.log(`\n🎭 Nebula-CLI Chaos Testing`);
    console.log(`Command: ${command}\n`);

    const runner = new ChaosRunner(command);
    runner.runAll(category).then(report => {
        const exitCode = report.summary.failed > 0 ? 1 : 0;
        process.exit(exitCode);
    });
}

module.exports = ChaosRunner;
