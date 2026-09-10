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

    static async simulateDiskPressure(options = {}) {
        const { bytes = 10 * 1024 * 1024, tmpFile = '/tmp/nebula-disk-pressure-test.tmp' } = options;
        return new Promise((resolve) => {
            const script = `                const fs = require('fs');
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

    static async simulateOOMKill(options = {}) {
        const { allocateMB = 512, timeoutMs = 10000 } = options;
        return new Promise((resolve) => {
            const script = `                const arrays = [];
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
     * Simulate a broken pipe (SIGPIPE/EPIPE) against the target CLI.
     * Spawns the target command, pipes its stdout into a downstream consumer,
     * then terminates the downstream process so the target's next write to the
     * pipe triggers EPIPE (Node) / SIGPIPE (POSIX default handling).
     * If no command is given, falls back to a self-contained high-volume writer.
     */
    static async injectStdIOBreak(options = {}) {
        const {
            command = null,
            args = ['--help'],
            pipeDuration = 100,
            downstream = 'node',
            downstreamArgs = ['-e', 'setInterval(() => {}, 50);'],
            timeoutMs = 10000
        } = options;
        return new Promise((resolve) => {
            let pipeBroken = false;
            let sigpipeTriggered = false;
            let stdoutData = '';
            let captured = false;

            const capture = (data) => {
                if (stdoutData.length < 1e6) {
                    stdoutData += data.toString();
                }
            };

            const done = (code, extra = {}) => {
                if (!captured) {
                    captured = true;
                    resolve({ code, pipeBroken, sigpipe: sigpipeTriggered, stdout: stdoutData, ...extra });
                }
            };

            const consumer = spawn(downstream, downstreamArgs, { timeout: timeoutMs });
            consumer.on('error', () => {});
            if (consumer.stdin) consumer.stdin.on('error', () => {});
            if (consumer.stdout) consumer.stdout.on('error', () => {});
            if (consumer.stderr) consumer.stderr.on('error', () => {});

            const child = command
                ? spawn(command, args, { timeout: timeoutMs })
                : spawn('node', ['-e', `const b = Buffer.alloc(65536, 0x61);
                    setInterval(() => { try { process.stdout.write(b); } catch (_) {} }, 1);`], { timeout: timeoutMs });

            child.stdout.pipe(consumer.stdin, { end: false });
            child.stdout.on('data', capture);
            child.stdout.on('error', (err) => {
                if (err.code === 'EPIPE') {
                    sigpipeTriggered = true;
                    pipeBroken = true;
                }
            });

            setTimeout(() => {
                pipeBroken = true;
                try { consumer.kill('SIGKILL'); } catch (_) {}
            }, pipeDuration);

            child.on('close', (code, signal) => {
                if (signal) {
                    sigpipeTriggered = true;
                    pipeBroken = true;
                }
                done(code, { signal });
            });
            child.on('error', (err) => {
                done(-1, { error: err.message });
            });
            setTimeout(() => {
                if (!captured) {
                    try { child.kill('SIGKILL'); } catch (_) {}
                    try { consumer.kill('SIGKILL'); } catch (_) {}
                    done(-1, { timedOut: true });
                }
            }, timeoutMs + 1000);
        });
    }

    /**
     * Inject random bytes (and optionally EOF) into the target CLI's stdin.
     */
    static async injectStdinRandomBytes(options = {}) {
        const {
            command = null,
            args = ['--stdin-input'],
            dataLength = 50,
            eofChance = 0.5,
            timeoutMs = 10000
        } = options;
        return new Promise((resolve) => {
            const randomBytes = [];
            for (let i = 0; i < dataLength; i++) {
                randomBytes.push(Math.floor(Math.random() * 256));
            }
            const randBuf = Buffer.from(randomBytes);
            const injectEof = Math.random() < eofChance;
            let stdoutData = '';

            const selfContainedScript = `
                process.stdin.resume();
                process.stdin.on('data', (data) => { process.stdout.write('RECEIVED: ' + data.length + '\n'); });
                process.stdin.on('end', () => { process.stdout.write('STDIN_ENDED\n'); process.exit(0); });
                const hexStr = Buffer.from(${JSON.stringify(randomBytes)}).toString('hex');
                process.stdin.push(Buffer.from(hexStr, 'hex'));
                ${injectEof ? 'process.stdin.destroy()' : 'setTimeout(() => { process.stdin.end(); process.exit(0); }, 100)'}
            `;

            const child = command
                ? spawn(command, args, { timeout: timeoutMs })
                : spawn('node', ['-e', selfContainedScript], { timeout: timeoutMs });

            child.stdout.on('data', (data) => { stdoutData += data.toString(); });
            child.stderr.on('data', (data) => { stdoutData += data.toString(); });

            if (command) {
                try {
                    child.stdin.write(randBuf);
                    if (injectEof) {
                        child.stdin.end();
                    } else {
                        setTimeout(() => { try { child.stdin.end(); } catch (_) {} }, 100);
                    }
                } catch (_) {}
            }

            child.on('close', (code) => {
                resolve({ code, injectedBytes: dataLength, injectedEof: injectEof, stdout: stdoutData });
            });
            child.on('error', (err) => {
                resolve({ code: -1, error: err.message, injectedBytes: dataLength, injectedEof: injectEof, stdout: stdoutData });
            });
        });
    }

    /**
     * Inject an immediate EOF into the target CLI's stdin.
     */
    static async injectStdinEOF(options = {}) {
        const {
            command = null,
            args = ['--stdin-input'],
            timeoutMs = 10000
        } = options;
        return new Promise((resolve) => {
            let stdoutData = '';
            const child = command
                ? spawn(command, args, { timeout: timeoutMs })
                : spawn('node', ['-e', `process.stdin.resume();
                     process.stdin.on('data', (data) => { process.stdout.write('RECEIVED: ' + data.length + '\n'); });
                     process.stdin.on('end', () => { process.stdout.write('STDIN_ENDED\n'); process.exit(0); });
                     process.stdin.destroy();`], { timeout: timeoutMs });

            child.stdout.on('data', (data) => { stdoutData += data.toString(); });

            if (command) {
                try { child.stdin.end(); } catch (_) {}
            }

            child.on('close', (code) => {
                resolve({ code, eofInjected: true, stdout: stdoutData });
            });
            child.on('error', (err) => {
                resolve({ code: -1, error: err.message, eofInjected: true, stdout: stdoutData });
            });
        });
    }

    /**
     * Throttle/delay reading of the target CLI's stdout to test for blocked IO.
     */
    static async throttleStdout(options = {}) {
        const {
            command = null,
            args = ['--help'],
            holdTime = 500,
            writeData = 'B'.repeat(100),
            timeoutMs = 10000
        } = options;
        return new Promise((resolve) => {
            let receivedData = '';
            let resolved = false;

            const child = command
                ? spawn(command, args, { timeout: timeoutMs })
                : spawn('node', ['-e', `const data = Buffer.from('${writeData}', 'utf8');
                     process.stdout.write(data, 'utf8', () => {
                         setTimeout(() => { process.exit(0); }, ${holdTime});
                     });`], { timeout: timeoutMs });

            setTimeout(() => {
                if (child.stdout) {
                    child.stdout.on('data', (data) => { receivedData += data.toString(); });
                }
            }, holdTime);

            child.on('close', (code) => {
                if (!resolved) {
                    resolved = true;
                    resolve({ code, heldTime: holdTime, stdout: receivedData, throttle: true });
                }
            });
            child.on('error', (err) => {
                if (!resolved) {
                    resolved = true;
                    resolve({ code: -1, error: err.message, stdout: receivedData, throttle: true });
                }
            });
            setTimeout(() => {
                if (!resolved) {
                    resolved = true;
                    try { child.kill('SIGTERM'); } catch (_) {}
                    resolve({ code: -1, heldTime: holdTime, stdout: receivedData, throttle: true, timedOut: true });
                }
            }, holdTime + timeoutMs);
        });
    }

    /**
     * Throttle/delay reading of the target CLI's stderr to test for blocked IO.
     */
    static async throttleStderr(options = {}) {
        const {
            command = null,
            args = ['--invalid-arg-tail'],
            holdTime = 500,
            writeData = 'C'.repeat(100),
            timeoutMs = 10000
        } = options;
        return new Promise((resolve) => {
            let stderrData = '';
            let resolved = false;

            const child = command
                ? spawn(command, args, { timeout: timeoutMs })
                : spawn('node', ['-e', `const data = Buffer.from('${writeData}', 'utf8');
                     process.stderr.write(data, 'utf8', () => {
                         setTimeout(() => { process.exit(0); }, ${holdTime});
                     });`], { timeout: timeoutMs });

            setTimeout(() => {
                if (child.stderr) {
                    child.stderr.on('data', (data) => { stderrData += data.toString(); });
                }
            }, holdTime);

            child.on('close', (code) => {
                if (!resolved) {
                    resolved = true;
                    resolve({ code, heldTime: holdTime, stderr: stderrData, throttle: true });
                }
            });
            child.on('error', (err) => {
                if (!resolved) {
                    resolved = true;
                    resolve({ code: -1, error: err.message, stderr: stderrData, throttle: true });
                }
            });
            setTimeout(() => {
                if (!resolved) {
                    resolved = true;
                    try { child.kill('SIGTERM'); } catch (_) {}
                    resolve({ code: -1, heldTime: holdTime, stderr: stderrData, throttle: true, timedOut: true });
                }
            }, holdTime + timeoutMs);
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
