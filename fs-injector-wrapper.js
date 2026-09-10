const { spawn } = require('child_process');
const path = require('path');

/**
 * Runs a command with the filesystem fault injector enabled.
 * 
 * @param {string} command - The command to run.
 * @param {string[]} args - The arguments for the command.
 * @param {Object} options - Options object.
 * @param {string} options.injectEaccesPath - Substring of path to inject EACCES.
 * @param {string} options.injectEnospcPath - Substring of path to inject ENOSPC.
 * @returns {Promise<{stdout: string, stderr: string, code: number}>}
 */
function runWithFsFaults(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        const env = { ...process.env };
        
        // Use a path relative to CWD or an absolute path (but ld.so has issues with spaces in LD_PRELOAD)
        // A safer way if the path has spaces is to just use the filename and rely on it being in the CWD
        // or a known library path. Let's assume the wrapper will be run where fs_injector.so is accessible,
        // e.g., if we spawn in __dirname.
        env.LD_PRELOAD = path.resolve(__dirname, 'fs_injector.so');
        // Wait, ld.so separates on spaces OR colons. If the absolute path has spaces, ld.so fails.
        // So let's just use a relative path from the CWD of the child process.
        // We will pass cwd: __dirname to spawn, and LD_PRELOAD = './fs_injector.so'
        env.LD_PRELOAD = './fs_injector.so';

        if (options.injectEaccesPath) {
            env.INJECT_EACCES_PATH = options.injectEaccesPath;
        }

        if (options.injectEnospcPath) {
            env.INJECT_ENOSPC_PATH = options.injectEnospcPath;
        }

        const child = spawn(command, args, { env, cwd: __dirname });

        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        child.on('close', (code) => {
            resolve({ stdout, stderr, code });
        });
        
        child.on('error', (err) => {
            reject(err);
        });
    });
}

module.exports = {
    runWithFsFaults
};
