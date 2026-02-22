/**
 * DoS & Memory Corruption Tests
 * Stress testing for denial of service and memory vulnerabilities
 */

const { spawn } = require('child_process');
const os = require('os');

class DoSTester {
    constructor(command = 'nebula') {
        this.command = command;
        this.results = [];
    }

    exec(args, timeout = 10000) {
        return new Promise((resolve) => {
            const proc = spawn(this.command, args, { shell: true });
            let stdout = '';
            let stderr = '';
            let timedOut = false;

            const timer = setTimeout(() => {
                timedOut = true;
                proc.kill('SIGKILL');
            }, timeout);

            proc.stdout.on('data', d => stdout += d.toString());
            proc.stderr.on('data', d => stderr += d.toString());
            proc.on('close', (code) => {
                clearTimeout(timer);
                resolve({ code, stdout, stderr, timedOut });
            });
            proc.on('error', (e) => {
                clearTimeout(timer);
                resolve({ code: -1, stdout: '', stderr: e.message, timedOut: false, error: true });
            });
        });
    }

    async testCPUStarvation() {
        console.log('\n🔥 CPU Starvation Test...');
        // Rapid fire commands to CPU starve
        const start = Date.now();
        const promises = [];
        for (let i = 0; i < 50; i++) {
            promises.push(this.exec(['--help'], 2000));
        }
        
        const results = await Promise.allSettled(promises);
        const duration = Date.now() - start;
        
        const successful = results.filter(r => r.status === 'fulfilled' && r.value.code === 0).length;
        
        return { 
            name: 'cpu_starvation', 
            passed: successful >= 40,
            details: `${successful}/50 succeeded in ${duration}ms`
        };
    }

    async testForkBomb() {
        console.log('🔥 Fork Bomb Simulation...');
        // Try commands that might spawn child processes
        const payloads = [
            'bash -c "echo $BASHPID"',
            '$(echo $(echo $(echo whoami)))',
            'true && true && true && true && true'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], 3000);
            if (!result.timedOut && result.code !== -1) passed++;
        }
        
        return { 
            name: 'fork_bomb', 
            passed: passed === payloads.length,
            details: `${passed}/${payloads.length} handled`
        };
    }

    async testHeapOverflow() {
        console.log('🔥 Heap Overflow Simulation...');
        // Send progressively larger inputs
        const sizes = [100000, 500000, 1000000, 2000000];
        
        let passed = 0;
        for (const size of sizes) {
            const input = 'A'.repeat(size);
            const result = await this.exec(['--input', input], 5000);
            if (!result.timedOut && !result.error) passed++;
        }
        
        return { 
            name: 'heap_overflow', 
            passed: passed >= 3,
            details: `${passed}/4 sizes handled`
        };
    }

    async testStackOverflow() {
        console.log('🔥 Stack Overflow Simulation...');
        // Deep recursion patterns
        const inputs = [
            '('.repeat(1000) + ')'.repeat(1000),
            '{{{{{'.repeat(100) + '}}}}}'.repeat(100),
            '['.repeat(10000) + ']'.repeat(10000)
        ];
        
        let passed = 0;
        for (const input of inputs) {
            const result = await this.exec(['--input', input], 3000);
            if (!result.timedOut) passed++;
        }
        
        return { 
            name: 'stack_overflow', 
            passed: passed === inputs.length,
            details: `${passed}/${inputs.length} handled`
        };
    }

    async testZipBomb() {
        console.log('🔥 Zip Bomb Simulation...');
        // Highly compressed-like patterns
        const patterns = [
            'PK' + '\x00'.repeat(10000),
            'ZIP' + 'X'.repeat(50000),
            '\x1f\x8b'.repeat(1000) // gzip magic
        ];
        
        let passed = 0;
        for (const pattern of patterns) {
            const result = await this.exec(['--input', pattern], 3000);
            if (!result.timedOut) passed++;
        }
        
        return { 
            name: 'zip_bomb', 
            passed: passed === patterns.length,
            details: `${passed}/${patterns.length} handled`
        };
    }

    async testAtomicBomb() {
        console.log('🔥 Atomic Bomb (Catastrophic Backtracking)...');
        // Regex catastrophic patterns
        const patterns = [
            'aaaaaaaaaaaaaaaaaaaaaa!',
            '(a+)+$'.repeat(10),
            '(.+)*$'.repeat(10),
            '(a|a|a)*$'.repeat(50)
        ];
        
        let passed = 0;
        for (const pattern of patterns) {
            const result = await this.exec(['--input', pattern], 2000);
            if (!result.timedOut) passed++;
        }
        
        return { 
            name: 'atomic_bomb', 
            passed: passed === patterns.length,
            details: `${passed}/${patterns.length} handled`
        };
    }

    async testResourceExhaustion() {
        console.log('🔥 Resource Exhaustion...');
        // Exhaust file descriptors, ports, etc.
        const startMem = process.memoryUsage().heapUsed;
        
        const promises = [];
        for (let i = 0; i < 100; i++) {
            promises.push(this.exec(['--version'], 1000));
        }
        
        await Promise.allSettled(promises);
        
        const endMem = process.memoryUsage().heapUsed;
        const memIncrease = (endMem - startMem) / 1024 / 1024;
        
        // Should not consume excessive memory
        return { 
            name: 'resource_exhaustion', 
            passed: memIncrease < 100,
            details: `Memory increase: ${memIncrease.toFixed(2)}MB`
        };
    }

    async testSlowLoris() {
        console.log('🔥 Slow Loris (Slow Request)...');
        // Send slowly
        const result = await new Promise((resolve) => {
            const proc = spawn(this.command, ['--input', 'test'], { shell: true });
            
            let received = false;
            
            proc.stdout.on('data', () => {
                if (!received) {
                    received = true;
                    setTimeout(() => {
                        proc.kill();
                        resolve({ slow: true, received });
                    }, 100);
                }
            });
            
            proc.stderr.on('data', () => {
                if (!received) {
                    received = true;
                    setTimeout(() => {
                        proc.kill();
                        resolve({ slow: true, received });
                    }, 100);
                }
            });
            
            setTimeout(() => {
                proc.kill();
                resolve({ slow: false, received });
            }, 3000);
        });
        
        return { 
            name: 'slow_loris', 
            passed: result.received,
            details: result.received ? 'Responsive' : 'Unresponsive'
        };
    }

    async testNullByteInjection() {
        console.log('🔥 Null Byte Injection...');
        const payloads = [
            'test\x00 malicious',
            'test\x00\x00\x00',
            '\x00'.repeat(100)
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], 3000);
            // Should handle without crash
            if (!result.error) passed++;
        }
        
        return { 
            name: 'null_byte', 
            passed: passed === payloads.length,
            details: `${passed}/${payloads.length} handled`
        };
    }

    async testIntegerOverflow() {
        console.log('🔥 Integer Overflow...');
        const payloads = [
            String(Number.MAX_SAFE_INTEGER),
            String(Number.MAX_VALUE),
            '-1',
            '999999999999999999999999'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], 3000);
            if (!result.error) passed++;
        }
        
        return { 
            name: 'integer_overflow', 
            passed: passed === payloads.length,
            details: `${passed}/${payloads.length} handled`
        };
    }

    async runAll() {
        console.log('\n╔══════════════════════════════════════════╗');
        console.log('║      DoS & MEMORY CORRUPTION SUITE     ║');
        console.log('╚══════════════════════════════════════════╝\n');

        const tests = [
            'testCPUStarvation',
            'testForkBomb',
            'testHeapOverflow',
            'testStackOverflow',
            'testZipBomb',
            'testAtomicBomb',
            'testResourceExhaustion',
            'testSlowLoris',
            'testNullByteInjection',
            'testIntegerOverflow'
        ];

        for (const test of tests) {
            try {
                const result = await this[test]();
                this.results.push(result);
                const status = result.passed ? '✅' : '❌';
                console.log(`${status} ${test}: ${result.details}`);
            } catch (e) {
                console.log(`❌ ${test}: ERROR - ${e.message}`);
                this.results.push({ name: test, passed: false, details: e.message });
            }
        }

        return this.results;
    }
}

async function main() {
    const tester = new DoSTester('nebula');
    await tester.runAll();
    
    const passed = tester.results.filter(r => r.passed).length;
    const total = tester.results.length;
    const percentage = Math.round(passed / total * 100);
    
    console.log('\n╔══════════════════════════════════════════╗');
    console.log(`║   FINAL: ${passed}/${total} Passed (${percentage}%)            ║`);
    console.log('╚══════════════════════════════════════════╝\n');
}

main();
