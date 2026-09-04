#!/usr/bin/env node
/**
 * Mock CLI fixture for chaos-runner self-tests.
 * Handles: --help, --version, --input <text>, --path <path>, --query/--search <text>
 * Unknown flags exit 1. Exits instantly (no sleeps).
 */

const args = process.argv.slice(2);

if (args.length === 0) {
  process.exit(1);
}

const flag = args[0];

if (flag === '--help') {
  console.log('Usage: mock-cli [options]');
  console.log('Options:');
  console.log('  --help       Show help');
  console.log('  --version    Show version');
  console.log('  --input <s>  Accept input');
  process.exit(0);
}

if (flag === '--version') {
  process.exit(0);
}

if (flag === '--input' || flag === '--path' || flag === '--query' || flag === '--search') {
  const value = args[1] || '';
  process.stdout.write('OK: ' + value.length + ' chars\n');
  process.exit(0);
}

if (flag === '--stdin-input') {
  let data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { data += chunk; });
  process.stdin.on('end', () => {
    process.stdout.write('OK: ' + data.length + ' chars from stdin\n');
    process.exit(0);
  });
} else {
  process.exit(1);
}
