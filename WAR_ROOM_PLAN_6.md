# WAR ROOM PLAN — Issue #6: Consolidate 3 test runners into single unified runner

## Analysis

**Current state:**
- `chaos-runner.js` (JS, 463 lines) — 15 real tests, all passing. Primary runner used by `npm test`.
- `chaos-monkey.py` (Python, 353 lines) — 7 stub tests (`lambda: None`), all trivially passing. Discard entirely.
- `dos-test.js` (JS, 324 lines) — 10 tests, 6 pass / 4 fail (null bytes, E2BIG bugs). Good unique tests to preserve.

**Plan:** Merge best tests from all three into a single `test-runner.js` with shared JSON config (`chaos.config.json`). Discard stubs and broken mock-based security tests.

## Subtasks

- [x] Create `chaos.config.json` — shared configuration (command, categories, timeouts, test definitions)
- [x] Create `test-runner.js` — unified runner with all best tests from chaos-runner.js + dos-test.js
- [ ] Update `package.json` — point scripts to new runner, fix `main` field
- [ ] Remove old runners: `chaos-runner.js`, `chaos-monkey.py`, `dos-test.js`
- [ ] Run tests, verify all pass, fix any failures
- [ ] Final cleanup: delete plan file, commit, push
