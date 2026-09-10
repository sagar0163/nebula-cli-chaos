# WAR_ROOM_PLAN_7.md — Fix mock CLI to actually fail on bad input

## Current state
- WIP commit (4fcf6d7) already updated mock-cli.js to exit 1 on unknown flags/invalid input
- All fuzz tests pass, but `testMemoryStress` crashes with EPIPE because `--stdin-input` flag is unknown to mock-cli
- test-runner.js exec() doesn't handle EPIPE on stdin writes

## Checklist

- [ ] Add `--stdin-input` flag support to mock-cli.js (reads from stdin, validates, exits 0/1)
- [ ] Fix EPIPE crash in test-runner.js exec() by handling stdin write errors gracefully
- [ ] Verify all test categories pass: basic, fuzz, memory, concurrency, stress, network
- [ ] Clean up: delete WAR_ROOM_PLAN_7.md, final commit, push
