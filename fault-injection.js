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

    static async injectStdIOBreak(options = {}) {
        const { pipeDuration = 100, writeData = 'A'.repeat(100) } = options;
        return new Promise((resolve) => {
            let pipeClosed = false;
            let sigpipeTriggered = false;
            let stdoutData = '';

            const child = spawn('node', ['-e', `const { spawn } = require('child_process');
                 const child2 = spawn('node', ['-e', 'process.exit(0)']);
                 process.stdout.write(Buffer.from('${writeData}')).write('\n');
                 setTimeout(() => { process.exit(0); }, ${pipeDuration});
                 child2.kill('SIGKILL');`], { timeout: 10000 });

            child.stdout.on('data', (data) => { stdoutData += data.toString(); });

            setTimeout(() => {
                if (child.stdout && !pipeClosed) {
                    pipeClosed = true;
                    try { child.stdout.destroy(); } catch (_) {}
                    sigpipeTriggered = true;
                }
            }, pipeDuration);

            child.on('close', (code) => {
                resolve({
                    code,
                    stdout: stdoutData,
                    sigpipe: sigpipeTriggered,
                    pipeClosed
                });
            });
            child.on('error', (err) => {
                resolve({ code: -1, error: err.message, stdout: stdoutData });
            });
        });
    }

    static async injectStdinRandomBytes(options = {}) {
        const { dataLength = 50, eofChance = 0.5 } = options;
        return new Promise((resolve) => {
            const randomBytes = [];
            for (let i = 0; i < dataLength; i++) {
                randomBytes.push(Math.floor(Math.random() * 256));
            }
            const randBuf = Buffer.from(randomBytes);

            const injectEof = Math.random() < eofChance;

            const child = spawn('node', ['-e', `const fs = require('fs');
                 process.stdin.resume();
                 process.stdin.on('data', (data) => { process.stdout.write('RECEIVED: ' + data.toString().length + '\n'); });
                 process.stdin.on('end', () => { process.stdout.write('STDIN_ENDED\n'); process.exit(0); });
                 const hexStr = Buffer.from(${JSON.stringify(randomBytes)}).toString('hex');
                 process.stdin.push(Buffer.from(hexStr, 'hex'));
                 ${injectEof ? 'process.stdin.destroy()' : 'setTimeout(() => { process.stdin.end(); process.exit(0); }, 100)'}`], { timeout: 10000 });

            let stdoutData = '';
            child.stdout.on('data', (data) => { stdoutData += data.toString(); });

            child.on('close', (code) => {
                resolve({
                    code,
                    injectedBytes: dataLength,
                    injectedEof: injectEof,
                    stdout: stdoutData
                });
            });
            child.on('error', (err) => {
                resolve({ code: -1, error: err.message, stdout: stdoutData });
            });
        });
    }

    static async injectStdinEOF(options = {}) {
        return new Promise((resolve) => {
            const child = spawn('node', ['-e', `process.stdin.resume();
                 process.stdin.on('data', (data) => { process.stdout.write('RECEIVED: ' + data.toString().length + '\n'); });
                 process.stdin.on('end', () => { process.stdout.write('STDIN_ENDED\n'); process.exit(0); });
                 process.stdin.destroy();`], { timeout: 10000 });

            let stdoutData = '';
            child.stdout.on('data', (data) => { stdoutData += data.toString(); });

            child.on('close', (code) => {
                resolve({
                    code,
                    eofInjected: true,
                    stdout: stdoutData
                });
            });
            child.on('error', (err) => {
                resolve({ code: -1, error: err.message, stdout: stdoutData });
            });
        });
    }

    static async throttleStdout(options = {}) {
        const { holdTime = 500, writeData = 'B'.repeat(100) } = options;
        return new Promise((resolve) => {
            let receivedData = '';
            let resolved = false;
            const child = spawn('node', ['-e', `const fs = require('fs');
                 const data = Buffer.from('${writeData}', 'utf8');
                 process.stdout.write(data, 'utf8', () => {
                     setTimeout(() => { process.exit(0); }, ${holdTime});
                 });`], { timeout: 10000 });

            child.stdout.on('data', (data) => { receivedData += data.toString(); });

            setTimeout(() => {
                child.kill('SIGTERM');
                resolved = true;
                resolve({
                    code: 0,
                    heldTime: holdTime,
                    stdout: receivedData,
                    throttle: true
                });
            }, holdTime + 1000);

            child.on('close', (code) => {
                if (!resolved) {
                    resolved = true;
                    resolve({
                        code,
                        heldTime: holdTime,
                        stdout: receivedData,
                        throttle: true
                    });
                }
            });
            child.on('error', (err) => {
                resolve({ code: -1, error: err.message, stdout: receivedData });
            });
        });
    }

    static async throttleStderr(options = {}) {
        const { holdTime = 500, writeData = 'C'.repeat(100) } = options;
        return new Promise((resolve) => {
            let stderrData = '';
            let resolved = false;
            const child = spawn('node', ['-e', `const fs = require('fs');
                 const data = Buffer.from('${writeData}', 'utf8');
                 process.stderr.write(data, 'utf8', () => {
                     setTimeout(() => { process.exit(0); }, ${holdTime});
                 });`], { timeout: 10000 });

            child.stderr.on('data', (data) => { stderrData += data.toString(); });

            setTimeout(() => {
                child.kill('SIGTERM');
                resolved = true;
                resolve({
                    code: 0,
                    heldTime: holdTime,
                    stderr: stderrData,
                    throttle: true
                });
            }, holdTime + 1000);

            child.on('close', (code) => {
                if (!resolved) {
                    resolved = true;
                    resolve({
                        code,
                        heldTime: holdTime,
                        stderr: stderrData,
                        throttle: true
                    });
                }
            });
            child.on('error', (err) => {
                resolve({ code: -1, error: err.message, stderr: stderrData });
            });
        });
    }
}

module.exports = FaultInjector;
