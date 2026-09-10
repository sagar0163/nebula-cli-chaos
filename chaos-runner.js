#!/usr/bin/env node

const ChaosTestRunner = require('./test-runner');
const packageJson = require('./package.json');

const args = process.argv.slice(2);

if (args.length === 0) {
    runTests(args);
    return;
}

const command = args[0];

if (command === '--help' || command === '-h') {
    console.log(`Usage:
  nebula-chaos run <config>
  nebula-chaos report [options]
  nebula-chaos metrics [options]
  nebula --help
  nebula --version
`);
    process.exit(0);
}

if (command === '--version' || command === '-v') {
    console.log(packageJson.version);
    process.exit(0);
}

if (command === 'run') {
    const configPath = args[1] || 'chaos.config.json';
    try {
        const runner = new ChaosTestRunner(configPath);
        runner.runAll('all').then(report => {
            const exitCode = report.summary.failed > 0 ? 1 : 0;
            process.exit(exitCode);
        });
    } catch (e) {
        console.error(e.message);
        process.exit(1);
    }
} else if (command === 'report' || command === 'metrics') {
    console.log(`Command '${command}' is not implemented yet.`);
    process.exit(0);
} else {
    runTests(args);
}

function runTests(argsArray) {
    const category = argsArray.find(a => a.startsWith('--category='))?.split('=')[1] || 'all';
    const configPath = argsArray.find(a => a.startsWith('--config='))?.split('=')[1] || 'chaos.config.json';
    const cmd = argsArray.find(a => !a.startsWith('--') && a !== 'run') || undefined;

    try {
        const runner = new ChaosTestRunner(configPath);
        if (cmd) {
            runner.command = cmd;
        }
        runner.runAll(category).then(report => {
            const exitCode = report.summary.failed > 0 ? 1 : 0;
            process.exit(exitCode);
        });
    } catch (e) {
        console.error(e.message);
        process.exit(1);
    }
}
