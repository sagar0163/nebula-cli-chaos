/**
 * Performance Benchmark Tests
 * Measure and compare CLI performance
 */

class PerformanceBenchmark {
    constructor(command = 'nebula') {
        this.command = command;
        this.results = [];
    }

    /**
     * Measure command execution time
     */
    async measureExecution(args = [], iterations = 10) {
        const times = [];
        
        for (let i = 0; i < iterations; i++) {
            const start = process.hrtime.bigint();
            await this.exec(args);
            const end = process.hrtime.bigint();
            times.push(Number(end - start) / 1000000); // Convert to ms
        }
        
        return {
            mean: times.reduce((a, b) => a + b) / times.length,
            min: Math.min(...times),
            max: Math.max(...times),
            median: this.median(times),
            stdDev: this.stdDev(times)
        };
    }

    median(arr) {
        const sorted = [...arr].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    stdDev(arr) {
        const mean = arr.reduce((a, b) => a + b) / arr.length;
        const squareDiffs = arr.map(v => Math.pow(v - mean, 2));
        return Math.sqrt(squareDiffs.reduce((a, b) => a + b) / arr.length);
    }

    exec(args) {
        return new Promise((resolve) => {
            const proc = require('child_process').spawn(this.command, args);
            proc.on('close', () => resolve());
        });
    }

    /**
     * Run benchmarks
     */
    async runBenchmarks() {
        console.log('Running benchmarks...\n');
        
        // Benchmark various scenarios
        const benchmarks = [
            { name: 'help', args: ['--help'] },
            { name: 'version', args: ['--version'] },
            { name: 'empty_command', args: [] }
        ];

        for (const bench of benchmarks) {
            console.log(`Benchmarking: ${bench.name}`);
            const stats = await this.measureExecution(bench.args, 10);
            console.log(`  Mean: ${stats.mean.toFixed(2)}ms`);
            console.log(`  Min:  ${stats.min.toFixed(2)}ms`);
            console.log(`  Max:  ${stats.max.toFixed(2)}ms`);
            console.log('');
        }
    }
}

/**
 * Stress Test
 */
class StressTest {
    constructor(command = 'nebula') {
        this.command = command;
    }

    async runConcurrent(count = 50) {
        console.log(`Running stress test with ${count} concurrent processes...`);
        
        const start = Date.now();
        const promises = [];
        
        for (let i = 0; i < count; i++) {
            promises.push(this.exec(['--help']));
        }
        
        const results = await Promise.allSettled(promises);
        const duration = Date.now() - start;
        
        const successful = results.filter(r => r.status === 'fulfilled').length;
        
        console.log(`Completed in ${duration}ms`);
        console.log(`Successful: ${successful}/${count}`);
        
        return { successful, failed: count - successful, duration };
    }

    exec(args) {
        return new Promise((resolve) => {
            const proc = require('child_process').spawn(this.command, args);
            proc.on('close', (code) => resolve(code));
            setTimeout(() => {
                proc.kill();
                resolve(-1);
            }, 5000);
        });
    }
}

module.exports = { PerformanceBenchmark, StressTest };
