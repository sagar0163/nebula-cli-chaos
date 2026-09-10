# WAR ROOM PLAN - Issue #15: Document the "Magic": Architecture of Rootless Execution

## Acceptance Criteria
- [x] Add a new section in the README or a dedicated `ARCHITECTURE.md` file
- [x] Explain explicitly that root privileges are not required
- [x] Detail the mechanisms used (e.g., LD_PRELOAD, DYLD_INSERT_LIBRARIES, API hooking, or proxying)
- [x] Clarify the cross-platform capabilities and limitations (Linux vs macOS vs Windows)

## Current Status

### `specs/ARCHITECTURE.md` - Already implemented in commit 36796ea
- **Rootless explanation**: Present in Design Philosophy section - "no root privileges, no kernel modules, no eBPF, no `tc netem`, no `/etc/hosts` modifications, no `iptables` rules"
- **Mechanisms detailed**: LD_PRELOAD / DYLD_INSERT_LIBRARYIS mechanism with full explanation of how it works, what it intercepts (open(), write()), and environment variable configuration
- **Cross-platform**: Comprehensive table covering Linux (full), macOS (partial - DYLD_INSERT_LIBRARIES), Windows (not supported - no LD_PRELOAD)
- **What it is NOT**: Explicit list of 7 things nebula-chaos does NOT use (sudo, eBPF, tc netem, kernel modules, iptables, /etc/hosts modification, ptrace)

### `README.md` - Already updated in commit f0a4d8c
- **Rootless claim**: "**No root required.** All fault injection runs entirely in user space using standard POSIX and Node.js mechanisms — no eBPF, no kernel modules, no `sudo`, no `tc netem`."
- **Mechanisms summary table**: child_process spawning, LD_PRELOAD/DYLD_INSERT_LIBRARIES, environment variable pass-through, DNS poison via `.invalid` TLD
- **Links to full ARCHITECTURE.md**: "> **For the full architectural breakdown** — cross-platform details, the `LD_PRELOAD` mechanism explained, security considerations, and component diagrams — see [`specs/ARCHITECTURE.md`](specs/ARCHITECTURE.md)."

## Checklist Verification
- [x] Root privileges explicitly stated as not required
- [x] LD_PRELOAD mechanism detailed with dlsym(RTLD_NEXT, ...) pattern
- [x] DYLD_INSERT_LIBRARIES mentioned for macOS
- [x] Cross-platform capabilities documented (Linux full, macOS partial, Windows not supported)
- [x] Acceptance criteria all satisfied

## Remaining Work
- [ ] Verify tests pass (npm test requires `nebula` binary - not installed globally)
- [ ] Ensure git commits are incremental
- [ ] Delete WAR_ROOM_PLAN_15.md after completion (scratch file, not part of product)