# WAR_ROOM_PLAN_12: Standard Stream & Pipe Break Faults

## Status: In Progress

### Already Complete (from prior commits)
- [x] `fault-injection.js`: `injectStdIOBreak` (SIGPIPE via pipe break)
- [x] `fault-injection.js`: `injectStdinRandomBytes` (random bytes + optional EOF into stdin)
- [x] `fault-injection.js`: `injectStdinEOF` (immediate EOF into stdin)
- [x] `fault-injection.js`: `throttleStdout` (hold stdout buffer)
- [x] `fault-injection.js`: `throttleStderr` (hold stderr buffer)
- [x] `test-runner.js`: all 5 test methods (`testFaultStdinBreak`, `testFaultStdinRandomBytes`, `testFaultStdinEOF`, `testFaultStdoutThrottle`, `testFaultStderrThrottle`)
- [x] `chaos.config.json`: tests registered in `fault-injection` and `all` categories

### This Session
- [x] Update README.md fault types table to include Stream/Pipe faults
- [x] Add YAML configuration examples for stdio faults to README.md
- [x] Update specs/BRD.md to mention stdio/pipe fault injection
- [x] Make stdio injectors target the actual CLI (command/args), cap buffers, detect signal death, defer pipe-read until after hold to fake blocked IO
- [x] Commit: target-aware injectors + docs (7667239)
- [x] Remove accidental chaos-report-*.json test artifacts from branch (aligns with #7 convention)
- [ ] Run full test suite (all categories) to verify no regressions
- [ ] Delete WAR_ROOM_PLAN_12.md and final commit
- [ ] Push branch
