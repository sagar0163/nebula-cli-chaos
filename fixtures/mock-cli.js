#!/usr/bin/env node
/** 
 * Mock CLI fixture for chaos-runner self-tests.
 * Handles: --help, --version, --input <text>, --path <path>, --query/--search <text>
 * Unknown flags exit 1. Invalid/unsafe input exits 1.
 * Exits instantly (no sleeps).
 */

const args = process.argv.slice(2);

if (args.length === 0) {
  process.exit(1);
}

const flag = args[0];

// --help: show help and exit 0
if (flag === '--help') {
  console.log('Usage: mock-cli [options]');
  console.log('Options:');
  console.log('  --help       Show help');
  console.log('  --version    Show version');
  console.log('  --input <text>  Accept input');
  console.log('  --path <path>   Accept path');
  console.log('  --query <text>  Accept query');
  console.log('  --search <text>  Accept search');
  process.exit(0);
}

// --version: show version and exit 0
if (flag === '--version') {
  process.exit(0);
}

// Check for null bytes in any input
function hasNullBytes(str) {
  return str && str.includes('\0');
}

// Check for dangerous characters/patterns in input
function hasDangerousPatterns(str) {
  if (str == null) return true;
  // Command injection patterns
  const dangerousPatterns = [
    /;;/,
    /\|[|]/,
    /&[&]/,
    /\|\|/,
    /\$\([^)]*\)/,
    /`[^`]*`/,
    /;[^;]*rm/,
    /;[^;]*del/,
    /;[^/]*\.\./,
  ];
  for (const pattern of dangerousPatterns) {
    if (pattern.test(str)) return true;
  }
  return false;
}

// Validate input value
function validateInput(value) {
  if (value == null) return false;
  
  // Check for null bytes
  if (hasNullBytes(value)) return false;
  
  // Check length - reject extremely long input (over 10000 chars)
  if (value.length > 10000) return false;
  
  // Check for dangerous patterns (command injection)
  if (hasDangerousPatterns(value)) return false;
  
  return true;
}

// Handle --input <text>
if (flag === '--input') {
  const value = args[1] || '';
  
  // Validate the input value
  if (!validateInput(value)) {
    console.error('Error: Invalid or unsafe input detected');
    process.exit(1);
  }
  
  // Check for null bytes specifically
  if (hasNullBytes(value)) {
    console.error('Error: Input contains null bytes');
    process.exit(1);
  }
  
  // Check for extremely long input
  if (value.length > 10000) {
    console.error('Error: Input exceeds maximum length of 10000 characters');
    process.exit(1);
  }
  
  console.log('OK: ' + value.length + ' chars');
  process.exit(0);
}

// Handle --path <path>
if (flag === '--path') {
  const value = args[1] || '';
  
  // Validate the path value
  if (!validateInput(value)) {
    console.error('Error: Invalid or unsafe path detected');
    process.exit(1);
  }
  
  // Check for null bytes
  if (hasNullBytes(value)) {
    console.error('Error: Path contains null bytes');
    process.exit(1);
  }
  
  // Check for path traversal
  if (value.includes('..')) {
    console.error('Error: Path traversal detected');
    process.exit(1);
  }
  
  // Check for absolute paths
  if (value.startsWith('/')) {
    console.error('Error: Absolute path not allowed');
    process.exit(1);
  }
  
  // Check length
  if (value.length > 1000) {
    console.error('Error: Path exceeds maximum length of 1000 characters');
    process.exit(1);
  }
  
  console.log('OK: ' + value.length + ' chars');
  process.exit(0);
}

// Handle --query <text>
if (flag === '--query' || flag === '--search') {
  const value = args[1] || '';
  
  // Validate the query/search value
  if (!validateInput(value)) {
    console.error('Error: Invalid or unsafe query detected');
    process.exit(1);
  }
  
  // Check for null bytes
  if (hasNullBytes(value)) {
    console.error('Error: Query contains null bytes');
    process.exit(1);
  }
  
  // Check length
  if (value.length > 1000) {
    console.error('Error: Query exceeds maximum length of 1000 characters');
    process.exit(1);
  }
  
  console.log('OK: ' + value.length + ' chars');
  process.exit(0);
}

// Unknown flag: exit 1
console.error('Error: Unknown flag: ' + flag);
process.exit(1);