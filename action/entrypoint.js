const fs = require('fs');
const path = require('path');
const https = require('https');

const CHAOS_PROFILES = {
  standard: {
    command: '',
    defaultTimeout: 10000,
    categories: {
      all: [
        'testHelpCommand',
        'testInvalidArgs',
        'testEmptyInput',
        'testConcurrency',
        'testSpecialChars',
        'testUnicode',
        'testLongInput',
        'testRapidFire',
        'testExtremeConcurrency',
        'testMemoryStress',
        'testDeepNesting',
        'testCommandInjection',
        'testJsonBomb',
        'testRedos',
        'testZombieDetection',
        'testForkBomb',
        'testAtomicBomb',
        'testResourceExhaustion',
        'testSlowLoris'
      ]
    },
    tests: {
      testHelpCommand: { category: 'basic', timeout: 5000 },
      testInvalidArgs: { category: 'fuzz', timeout: 5000 },
      testEmptyInput: { category: 'basic', timeout: 5000 },
      testConcurrency: { category: 'concurrency', timeout: 15000 },
      testSpecialChars: { category: 'fuzz', timeout: 5000 },
      testUnicode: { category: 'fuzz', timeout: 5000 },
      testLongInput: { category: 'memory', timeout: 10000 },
      testRapidFire: { category: 'concurrency', timeout: 15000 },
      testExtremeConcurrency: { category: 'stress', timeout: 30000 },
      testMemoryStress: { category: 'memory', timeout: 20000 },
      testDeepNesting: { category: 'stress', timeout: 10000 },
      testCommandInjection: { category: 'fuzz', timeout: 10000 },
      testJsonBomb: { category: 'stress', timeout: 10000 },
      testRedos: { category: 'fuzz', timeout: 10000 },
      testZombieDetection: { category: 'concurrency', timeout: 15000 },
      testForkBomb: { category: 'concurrency', timeout: 10000 },
      testAtomicBomb: { category: 'fuzz', timeout: 10000 },
      testResourceExhaustion: { category: 'stress', timeout: 15000 },
      testSlowLoris: { category: 'network', timeout: 10000 }
    }
  },
  offline: {
    command: '',
    defaultTimeout: 10000,
    categories: {
      all: [
        'testConcurrency',
        'testRapidFire',
        'testExtremeConcurrency',
        'testSlowLoris',
        'testFaultLatency',
        'testFaultDNSFailure',
        'testFaultDNSFailureViaProcess'
      ]
    },
    tests: {
      testConcurrency: { category: 'concurrency', timeout: 15000 },
      testRapidFire: { category: 'concurrency', timeout: 15000 },
      testExtremeConcurrency: { category: 'stress', timeout: 30000 },
      testSlowLoris: { category: 'network', timeout: 10000 },
      testFaultLatency: { category: 'fault-injection', timeout: 10000 },
      testFaultDNSFailure: { category: 'fault-injection', timeout: 10000 },
      testFaultDNSFailureViaProcess: { category: 'fault-injection', timeout: 10000 }
    }
  },
  'disk-pressure': {
    command: '',
    defaultTimeout: 10000,
    categories: {
      all: [
        'testFaultDiskPressure',
        'testLongInput',
        'testMemoryStress',
        'testJsonBomb',
        'testResourceExhaustion'
      ]
    },
    tests: {
      testFaultDiskPressure: { category: 'fault-injection', timeout: 30000 },
      testLongInput: { category: 'memory', timeout: 10000 },
      testMemoryStress: { category: 'memory', timeout: 20000 },
      testJsonBomb: { category: 'stress', timeout: 10000 },
      testResourceExhaustion: { category: 'stress', timeout: 15000 }
    }
  },
  'flaky-env': {
    command: '',
    defaultTimeout: 10000,
    categories: {
      all: [
        'testFaultLatency',
        'testFaultOOMKill',
        'testFaultProcessKill',
        'testZombieDetection',
        'testForkBomb',
        'testConcurrency',
        'testRapidFire'
      ]
    },
    tests: {
      testFaultLatency: { category: 'fault-injection', timeout: 10000 },
      testFaultOOMKill: { category: 'fault-injection', timeout: 15000 },
      testFaultProcessKill: { category: 'fault-injection', timeout: 10000 },
      testZombieDetection: { category: 'concurrency', timeout: 15000 },
      testForkBomb: { category: 'concurrency', timeout: 10000 },
      testConcurrency: { category: 'concurrency', timeout: 15000 },
      testRapidFire: { category: 'concurrency', timeout: 15000 }
    }
  }
};

function getInput(name, defaultValue = '') {
  const envName = `INPUT_${name.replace(/-/g, '_').toUpperCase()}`;
  return process.env[envName] || defaultValue;
}

function setOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath) {
    fs.appendFileSync(outputPath, `${name}=${value}\n`);
  }
}

function generateMarkdownReport(report) {
  const { summary, results, command, profile } = report;
  const passed = summary.passed;
  const failed = summary.failed;
  const total = summary.total;
  const passRate = summary.passRate;

  const statusEmoji = failed === 0 ? ':white_check_mark:' : ':x:';
  const statusText = failed === 0 ? 'All tests passed' : `${failed} test(s) failed`;

  let md = `## ${statusEmoji} Nebula Chaos Test Report\n\n`;
  md += `**Command:** \`${command}\`\n`;
  md += `**Profile:** ${profile}\n`;
  md += `**Duration:** ${(summary.durationMs / 1000).toFixed(1)}s\n\n`;
  md += `### Summary\n\n`;
  md += `| Metric | Value |\n`;
  md += `|--------|-------|\n`;
  md += `| Total Tests | ${total} |\n`;
  md += `| Passed | ${passed} |\n`;
  md += `| Failed | ${failed} |\n`;
  md += `| Pass Rate | ${passRate} |\n\n`;

  if (failed > 0) {
    md += `### Failed Tests\n\n`;
    md += `| Test | Error |\n`;
    md += `|------|-------|\n`;
    for (const result of results) {
      if (!result.passed) {
        md += `| ${result.name} | ${result.error || 'Test failed'} |\n`;
      }
    }
    md += `\n`;
  }

  md += `### All Tests\n\n`;
  md += `<details>\n<summary>Click to expand test results</summary>\n\n`;
  md += `| Test | Status | Output |\n`;
  md += `|------|--------|--------|\n`;
  for (const result of results) {
    const emoji = result.passed ? ':white_check_mark:' : ':x:';
    const output = (result.output || '').substring(0, 100).replace(/\|/g, '\\|').replace(/\n/g, ' ');
    md += `| ${result.name} | ${emoji} | ${output} |\n`;
  }
  md += `\n</details>\n\n`;

  md += `---\n*Generated by [Nebula CLI Chaos](https://github.com/sagar0163/nebula-cli-chaos) v2.0.0*\n`;

  return md;
}

async function postPRComment(report) {
  const githubToken = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const pullNumber = process.env.PR_NUMBER || (process.env.GITHUB_REF || '').match(/(\d+)\/merge/)?.[1];

  if (!githubToken || !repo || !pullNumber) {
    console.log('Skipping PR comment (not a PR event or missing token)');
    return;
  }

  const markdown = generateMarkdownReport(report);
  const body = `## 🎭 Nebula Chaos Test Results\n\n${markdown}`;

  const data = JSON.stringify({ body });

  const options = {
    hostname: 'api.github.com',
    path: `/repos/${repo}/issues/${pullNumber}/comments`,
    method: 'POST',
    headers: {
      'Authorization': `token ${githubToken}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent': 'nebula-chaos-action',
      'Content-Length': Buffer.byteLength(data)
    }
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          console.log('PR comment posted successfully');
          resolve();
        } else {
          console.log(`Failed to post PR comment: ${res.statusCode} ${body}`);
          resolve();
        }
      });
    });
    req.on('error', (err) => {
      console.log(`Failed to post PR comment: ${err.message}`);
      resolve();
    });
    req.write(data);
    req.end();
  });
}

async function main() {
  const command = getInput('command', 'echo');
  const profile = getInput('profile', 'standard');
  const configPath = getInput('config-path');
  const timeout = parseInt(getInput('timeout', '10000'), 10);
  const failOnFailure = getInput('fail-on-failure', 'true') === 'true';
  const postComment = getInput('post-comment', 'true') === 'true';

  console.log(`\n🎭 Nebula CLI Chaos Action`);
  console.log(`Command: ${command}`);
  console.log(`Profile: ${profile}\n`);

  let config;
  if (configPath && fs.existsSync(configPath)) {
    console.log(`Using custom config: ${configPath}`);
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } else if (CHAOS_PROFILES[profile]) {
    console.log(`Using profile: ${profile}`);
    config = { ...CHAOS_PROFILES[profile], command };
  } else {
    console.error(`Unknown profile: ${profile}. Available: ${Object.keys(CHAOS_PROFILES).join(', ')}`);
    process.exit(1);
  }

  config.defaultTimeout = timeout;
  config.reportDir = '.';

  const tempConfigPath = path.join(process.env.RUNNER_TEMP || '/tmp', 'chaos.config.json');
  fs.writeFileSync(tempConfigPath, JSON.stringify(config, null, 2));
  console.log(`Generated config: ${tempConfigPath}\n`);

  const ChaosTestRunner = require('../test-runner');
  const runner = new ChaosTestRunner(tempConfigPath);
  runner.command = command.split(/\s+/)[0];
  runner.commandArgs = command.split(/\s+/).slice(1);

  const report = await runner.runAll('all');
  report.profile = profile;

  const summary = `${report.summary.passed} passed, ${report.summary.failed} failed, ${report.summary.total} total`;
  console.log(`\n${summary}\n`);

  const markdown = generateMarkdownReport(report);
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, markdown);
    console.log('Report written to GitHub Actions Summary');
  }

  const reportJsonPath = path.join(process.cwd(), `chaos-report-action-${Date.now()}.json`);
  fs.writeFileSync(reportJsonPath, JSON.stringify(report, null, 2));
  console.log(`JSON report: ${reportJsonPath}`);

  setOutput('report-json', reportJsonPath);
  setOutput('summary', summary);
  setOutput('exit-code', report.summary.failed > 0 ? '1' : '0');

  if (postComment) {
    await postPRComment(report);
  }

  try {
    fs.unlinkSync(tempConfigPath);
  } catch (e) {}

  if (failOnFailure && report.summary.failed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Action failed:', err);
  process.exit(1);
});
