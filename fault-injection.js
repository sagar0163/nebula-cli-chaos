/**
 * Node.js Native Fault Injection Module
 * ======================================
 * Provides fault injection using only Node.js built-in capabilities
 * (child_process, timeouts, resource limits) — no tc netem, no toxiproxy.
 */

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const http = require('http');
const os = require('os');

class FaultInjector {
    /**
     * Simulate network latency by spawning a process with an artificial delay.
     * Uses setTimeout + child_process to inject latency into command execution.
     */
    static async injectLatency(delayMs = 2000) {
        const start = Date.now();
        return new Promise((resolve) => {
            const proc = spawn('node', ['-e', `setTimeout(() => process.exit(0), ${delayMs})`], {
                timeout: delayMs + 5000
            });
            proc.on('close', (code) => {
                const elapsed = Date.now() - start;
                resolve({ code, elapsed, injected: elapsed >= delayMs * 0.9 });
            });
            proc.on('error', (err) => {
                resolve({ code: -1, elapsed: Date.now() - start, injected: false, error: err.message });
            });
        });
    }

    /**
     * Simulate DNS failure by attempting to resolve a guaranteed-unresolvable host.
     * Returns the DNS error for assertion purposes.
     */
    static async simulateDNSFailure(hostname = 'this-host-does-not-exist-chaos-test.invalid') {
        return new Promise((resolve) => {
            dns.resolve4(hostname, (err) => {
                if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA' || err.code === 'ESERVFAIL')) {
                    resolve({ failed: true, errorCode: err.code, hostname });
                } else if (err) {
                    resolve({ failed: true, errorCode: err.code || 'UNKNOWN', hostname });
                } else {
                    resolve({ failed: false, hostname });
                }
            });
        });
    }

    /**
     * Simulate DNS failure via child_process by curling a mock unresolvable host.
     * Uses the system resolver but via an external process (no root needed).
     */
    static async simulateDNSFailureViaProcess(hostname = 'this-host-does-not-exist-chaos-test.invalid', timeoutMs = 5000) {
        return new Promise((resolve) => {
            const start = Date.now();
            const proc = spawn('node', [
                '-e',
                `require('dns').lookup('${hostname}', (err) => { process.exit(err ? 1 : 0); })`
            ], { timeout: timeoutMs });

            let stderr = '';
            proc.stderr.on('data', (d) => { stderr += d; });

            proc.on('close', (code) => {
                resolve({ failed: code !== 0, code, elapsed: Date.now() - start, hostname });
            });
            proc.on('error', (err) => {
                resolve({ failed: true, code: -1, elapsed: Date.now() - start, error: err.message, hostname });
            });
        });
    }

    /**
     * Simulate disk pressure by writing a large file using child_process.
     * Uses dd-like approach with node to fill available space, then cleans up.
     * Sets ulimit via child_process resource limits to constrain write.
     */
    static async simulateDiskPressure(options = {}) {
        const { bytes = 10 * 1024 * 1024, tmpFile = '/tmp/nebula-disk-pressure-test.tmp' } = options;
        return new Promise((resolve) => {
            const script = `
                const fs = require('fs');
                const buf = Buffer.alloc(1024, 0x41);
                const fd = fs.openSync('${tmpFile}', 'w');
                let written = 0;
                try {
                    while (written < ${bytes}) {
                        fs.writeSync(fd, buf);
                        written += buf.length;
                    }
                    fs.closeSync(fd);
                    process.exit(0);
                } catch (e) {
                    try { fs.closeSync(fd); } catch(_){}
                    try { fs.unlinkSync('${tmpFile}'); } catch(_){}
                    process.exit(1);
                }
            `;
            const proc = spawn('node', ['-e', script], { timeout: 30000 });
            let stderr = '';
            proc.stderr.on('data', (d) => { stderr += d; });

            proc.on('close', (code) => {
                let actualSize = 0;
                try {
                    const stat = fs.statSync(tmpFile);
                    actualSize = stat.size;
                    fs.unlinkSync(tmpFile);
                } catch (_) {}
                resolve({ code, requestedBytes: bytes, writtenBytes: actualSize, success: code === 0 });
            });
            proc.on('error', (err) => {
                resolve({ code: -1, requestedBytes: bytes, writtenBytes: 0, error: err.message });
            });
        });
    }

    /**
     * Simulate OOM kill by allocating excessive memory in a child process.
     * The child process will be killed when it exceeds memory limits.
     */
    static async simulateOOMKill(options = {}) {
        const { allocateMB = 512, timeoutMs = 10000 } = options;
        return new Promise((resolve) => {
            const script = `
                const arrays = [];
                try {
                    while (true) {
                        arrays.push(Buffer.alloc(1024 * 1024, 0x42));
                    }
                } catch (e) {
                    process.exit(137);
                }
            `;
            const start = Date.now();
            const proc = spawn('node', ['--max-old-space-size=' + allocateMB, '-e', script], {
                timeout: timeoutMs
            });

            let killed = false;
            proc.on('close', (code) => {
                killed = code === 137 || code === null || code === -1;
                resolve({ killed, code, elapsed: Date.now() - start, allocateMB });
            });
            proc.on('error', (err) => {
                resolve({ killed: true, code: -1, elapsed: Date.now() - start, error: err.message });
            });

            setTimeout(() => {
                if (!proc.killed) {
                    proc.kill('SIGKILL');
                    killed = true;
                }
            }, timeoutMs);
        });
    }

    /**
     * Simulate process kill via SIGKILL after resource exhaustion.
     */
    static async simulateProcessKill(signal = 'SIGKILL', timeoutMs = 5000) {
        return new Promise((resolve) => {
            const proc = spawn('node', ['-e', 'setInterval(() => {}, 100);'], { timeout: timeoutMs });
            const start = Date.now();

            setTimeout(() => {
                proc.kill(signal);
            }, 1000);

            proc.on('close', (code) => {
                resolve({ killed: true, signal, code, elapsed: Date.now() - start });
            });
            proc.on('error', (err) => {
                resolve({ killed: true, signal, code: -1, error: err.message, elapsed: Date.now() - start });
            });
        });
    }

    /**
     * Corrupts environment variables in the provided env object.
     * Strategies: 'unset', 'truncate', 'invalid_chars'
     */
    static corruptEnvVar(envObj, key, strategy) {
        const newEnv = { ...envObj };
        if (strategy === 'unset') {
            delete newEnv[key];
        } else if (strategy === 'truncate') {
            if (newEnv[key]) {
                newEnv[key] = String(newEnv[key]).substring(0, Math.floor(String(newEnv[key]).length / 2));
            }
        } else if (strategy === 'invalid_chars') {
            if (newEnv[key]) {
                newEnv[key] = String(newEnv[key]) + '\uFFFD\xFF!@#$%^&*()';
            } else {
                newEnv[key] = '\uFFFD\xFF!@#$%^&*()';
            }
        }
        return newEnv;
    }

    static _configBackups = new Map();
    static _exitHooksSetup = false;

    static setupExitHooks() {
        if (FaultInjector._exitHooksSetup) return;
        FaultInjector._exitHooksSetup = true;
        const restoreAll = () => {
            for (const [filePath, backupData] of FaultInjector._configBackups.entries()) {
                try {
                    fs.writeFileSync(filePath, backupData);
                } catch(e) {}
            }
        };
        process.on('exit', restoreAll);
        process.on('SIGINT', () => { restoreAll(); process.exit(1); });
        process.on('SIGTERM', () => { restoreAll(); process.exit(1); });
        process.on('uncaughtException', (err) => { restoreAll(); console.error(err); process.exit(1); });
    }

    /**
     * Temporarily corrupts a config file.
     * Backs up the original and registers exit hooks to restore it.
     */
    static corruptConfigFile(filePath, strategy) {
        FaultInjector.setupExitHooks();
        const content = fs.readFileSync(filePath, 'utf8');
        if (!FaultInjector._configBackups.has(filePath)) {
            FaultInjector._configBackups.set(filePath, content);
        }

        let corrupted = content;
        if (strategy === 'malform_json') {
            corrupted = content.substring(0, Math.floor(content.length / 2)) + 'invalid_json_here{[';
        } else if (strategy === 'change_type') {
            try {
                const parsed = JSON.parse(content);
                for (const key in parsed) {
                    if (typeof parsed[key] === 'string') {
                        parsed[key] = 12345;
                        break;
                    }
                }
                corrupted = JSON.stringify(parsed);
            } catch(e) {
                corrupted = content + 'invalid';
            }
        }
        fs.writeFileSync(filePath, corrupted);
    }

    static restoreConfigFile(filePath) {
        if (FaultInjector._configBackups.has(filePath)) {
            const backupData = FaultInjector._configBackups.get(filePath);
            try {
                fs.writeFileSync(filePath, backupData);
            } catch(e) {}
            FaultInjector._configBackups.delete(filePath);
        }
    }
}

module.exports = FaultInjector;
