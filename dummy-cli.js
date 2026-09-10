#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const action = process.argv[2];
const targetPath = process.argv[3];

if (!action || !targetPath) {
    console.error('Usage: dummy-cli.js <read|write> <file>');
    process.exit(1);
}

try {
    if (action === 'read') {
        const content = fs.readFileSync(targetPath, 'utf8');
        console.log(`Read ${content.length} bytes`);
    } else if (action === 'write') {
        fs.writeFileSync(targetPath, 'test content', 'utf8');
        console.log('Write successful');
    } else {
        console.error('Unknown action');
        process.exit(1);
    }
} catch (error) {
    console.error(`Error: ${error.code} - ${error.message}`);
    process.exit(1);
}
