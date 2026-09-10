const { runWithFsFaults } = require('./fs-injector-wrapper');
const path = require('path');
const assert = require('assert');
const fs = require('fs');

async function runTests() {
    console.log('Running tests...');

    const dummyCli = path.join(__dirname, 'dummy-cli.js');
    const testFile = path.join(__dirname, 'test-file.txt');
    
    // Ensure test file exists
    fs.writeFileSync(testFile, 'hello world', 'utf8');

    // Test 1: Normal read (no fault)
    let result = await runWithFsFaults('node', [dummyCli, 'read', testFile]);
    assert.strictEqual(result.code, 0);
    assert.match(result.stdout, /Read \d+ bytes/);
    console.log('Test 1 passed');

    // Test 2: Inject EACCES on read
    result = await runWithFsFaults('node', [dummyCli, 'read', testFile], {
        injectEaccesPath: 'test-file.txt'
    });
    assert.strictEqual(result.code, 1);
    assert.match(result.stderr, /EACCES/);
    console.log('Test 2 passed');

    // Test 3: Normal write
    result = await runWithFsFaults('node', [dummyCli, 'write', testFile]);
    assert.strictEqual(result.code, 0);
    assert.match(result.stdout, /Write successful/);
    console.log('Test 3 passed');

    // Test 4: Inject ENOSPC on write
    result = await runWithFsFaults('node', [dummyCli, 'write', testFile], {
        injectEnospcPath: 'test-file.txt'
    });
    assert.strictEqual(result.code, 1);
    assert.match(result.stderr, /ENOSPC/);
    console.log('Test 4 passed');

    console.log('All tests passed!');
    
    // Cleanup
    fs.unlinkSync(testFile);
}

runTests().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
});
