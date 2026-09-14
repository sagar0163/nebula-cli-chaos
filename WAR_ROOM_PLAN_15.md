# WAR ROOM PLAN - Issue #15: Document the "Magic": Architecture of Rootless Execution

## Acceptance Criteria
- [x] Add a new section in the README or a dedicated `ARCHITECTURE.md` file
- [x] Explain explicitly that root privileges are not required
- [x] Detail the mechanisms used (e.g., LD_PRELOAD, DYLD_INSERT_LIBRARIES, API hooking, or proxying)
- [x] Clarify the cross-platform capabilities and limitations (Linux vs macOS vs Windows)

## What's Already Done (prior commits 36796ea -> 805b72d)
- `specs/ARCHITECTURE.md` — full rootless-execution breakdown (mechanisms, LD_PRELOAD internals,
  cross-platform matrix, "what this is NOT", component diagram, security)
- `README.md` — Architecture section rewritten: explicit "No root required" claim + summary table +
  link to `specs/ARCHITECTURE.md`
- Ran out of time before finishing verification; plan file was deleted prematurely.

## Remaining Work (this run)
- [ ] Fix `npm test`: `"test": "nebula"` fails with `nebula: not found` because npm does not
      self-link the root package's bins into `node_modules/.bin`. Change scripts to `node chaos-runner.js`.
- [ ] Run `npm test` to verify the suite passes (fault-injection + all categories)
- [ ] Confirm docs accuracy against actual source (fs-injector-wrapper.js, fault-injection.js,
      fs_injector.c, chaos-runner.js)
- [ ] Delete WAR_ROOM_PLAN_15.md (scratch) and make final commit referencing #15
- [ ] Push branch `war-room-issue-15` to origin