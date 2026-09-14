# WAR ROOM PLAN — Issue #15: Document the "Magic": Architecture of Rootless Execution

## Status
Prior attempts (commits 36796ea..bc8034d) completed the core documentation and test-script work.
This plan tracks the remaining verification + cleanup before the branch is finalized.

## Checklist
- [x] Write specs/ARCHITECTURE.md explaining rootless (user-space) interception mechanisms
- [x] Update README.md with an architecture section that links to specs/ARCHITECTURE.md
- [x] Explicitly state root/sudo/eBPF/kernel modules are NOT required
- [x] Detail mechanisms: child_process spawning, LD_PRELOAD/DYLD_INSERT_LIBRARIES, env-var injection, `.invalid` TLD DNS
- [x] Document cross-platform capabilities/limitations (Linux / macOS / Windows)
- [x] Fix npm test scripts to run via `node chaos-runner.js` (no global `nebula` bin dependency)
- [x] Remove stale generated `chaos-report-*.json` from git tracking and ignore report artifacts
- [x] Verify `npm test` passes (25/25) and `node test-fs-injector.js` passes
- [x] Remove remaining stale scratch artifacts tracked by accident (`*_<ts>.txt`, `x`)
- [ ] Re-run `npm test` + `node test-fs-injector.js` against the cleaned tree
- [ ] Final commit deleting this plan file, then push branch