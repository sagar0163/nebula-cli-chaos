# WAR_ROOM_PLAN_14.md - GitHub Action for Zero-Config CI Integration

## Issue #14: Create Official GitHub Action for Zero-Config CI Integration

### Subtask Checklist

- [x] Create action directory structure with action.yml
- [x] Create entrypoint.js (Node.js cross-platform entrypoint)
- [x] Add profile support (offline, disk-pressure, flaky-env) to the action
- [x] Implement HTML/Markdown report generation for GitHub Actions Summary
- [x] Add PR comment posting capability for reports
- [ ] Create action README with usage documentation
- [ ] Create example workflow file for users
- [ ] Test the action locally/verify it works
- [ ] Update main README.md with GitHub Action section
- [ ] Clean up and make final commit

### Design Notes

**Action Structure:**
- `action/` directory containing:
  - `action.yml` - GitHub Action metadata
  - `entrypoint.js` - Node.js entrypoint (cross-platform, no shell dependencies)
  - `package.json` - Dependencies for the action

**Profile Support:**
- `offline` - Tests network resilience (latency, DNS failure, etc.)
- `disk-pressure` - Tests filesystem resilience (disk full, IO errors)
- `flaky-env` - Tests environment variable manipulation and process signals
- `standard` - Default profile running all basic tests

**Report Generation:**
- Markdown report for GitHub Actions Summary (using `$GITHUB_STEP_SUMMARY`)
- JSON report for artifact upload
- PR comment posting via GitHub API when triggered by pull_request

**Cross-Platform:**
- Node.js-based entrypoint (works on Ubuntu, macOS, Windows)
- No root/sudo required
- Uses only Node.js built-in modules

### Implementation Steps

1. Create `action/` directory with `action.yml`
2. Create `action/entrypoint.js` that:
   - Reads action inputs (command, profile, config-path, timeout)
   - Generates chaos.config.json dynamically based on profile
   - Runs the chaos tests via ChaosTestRunner
   - Generates Markdown report
   - Writes to GITHUB_STEP_SUMMARY
   - Optionally posts PR comment
3. Create `action/package.json` with minimal dependencies
4. Create `action/README.md` with usage docs
5. Create `examples/chaos-action.yml` with example workflow
6. Update main README.md with GitHub Action section
