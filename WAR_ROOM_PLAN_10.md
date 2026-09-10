# War Room Plan — Issue #10: Clarify README value proposition and update documentation

All docs must describe the **actual** codebase: a local JSON-config-driven chaos test runner
(`test-runner.js` + `chaos.config.json` + `fault-injection.js`), invoked via the `nebula` /
`nebula-chaos` bins. No YAML experiments, no HTML/Prometheus reporting (yet).

- [x] Audit repo: read README, ARCHITECTURE.md, BRD.md, package.json, test-runner.js, chaos.config.json, fault-injection.js, chaos-runner.js, fixtures, CI workflows
- [x] Confirm real CLI surface (`--help`, `--version`, `run`, `--category=`, `--config=`; `report`/`metrics` not yet implemented)
- [ ] Fix package.json: `npm test` must work without global install (use `node chaos-runner.js`); add build script so release.yml's `npm run build` doesn't fail
- [ ] Add `.gitignore` for generated `chaos-report-*.json`; remove the stale committed report from git
- [ ] Rewrite README.md — who it's for, problem it solves, honest current vs. planned capabilities, working quick start, install instructions matching reality
- [ ] Rewrite specs/ARCHITECTURE.md — real component definitions, interfaces, data flows, config schema, report format
- [ ] Rewrite specs/BRD.md — user stories, acceptance criteria, success metrics
- [ ] Verify: `npm test` passes, quick-start commands work; commit everything incrementally
- [ ] Delete WAR_ROOM_PLAN_10.md, final commit referencing #10, push branch