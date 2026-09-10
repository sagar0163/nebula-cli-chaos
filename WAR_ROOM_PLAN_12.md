# WAR_ROOM_PLAN_12: Standard Stream & Pipe Break Faults

## Status: Resuming

### Already Complete (from prior commits)
- [x] `fault-injection.js`: `injectStdIOBreak` (SIGPIPE via pipe break)
- [x] `fault-injection.js`: `injectStdinRandomBytes` (random bytes + optional EOF into stdin)
- [x] `fault-injection.js`: `injectStdinEOF` (immediate EOF into stdin)
- [x] `fault-injection.js`: `throttleStdout` (hold stdout buffer)
- [x] `fault-injection.js`: `throttleStderr` (hold stderr buffer)
- [x] `test-runner.js`: all 5 test methods (`testFaultStdinBreak`, `testFaultStdinRandomBytes`, `testFaultStdinEOF`, `testFaultStdoutThrottle`, `testFaultStderrThrottle`)
- [x] `chaos.config.json`: tests registered in `fault-injection` and `all` categories
- [x] All tests pass

### Remaining Work
- [ ] Update README.md fault types table to include Stream/Pipe faults
- [ ] Add YAML configuration examples for stdio faults to README.md
- [ ] Update specs/BRD.md to mention stdio/pipe fault injection
- [ ] Run full test suite (all categories) to verify no regressions
- [ ] Delete WAR_ROOM_PLAN_12.md and final commit
- [ ] Push branch
