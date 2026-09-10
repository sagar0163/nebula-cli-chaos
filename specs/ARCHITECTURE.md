# Architecture: Rootless Fault Injection in nebula-cli-chaos

## Design Philosophy

`nebula-cli-chaos` intercepts and corrupts system calls at the **user-space level** — no root privileges, no kernel modules, no eBPF, no `tc netem`, no `/etc/hosts` modifications, no `iptables` rules. Every fault injection mechanism works within the standard POSIX process model and the Node.js runtime, making it safe to run in CI, local development, and sandboxed environments.

---

## Mechanism Overview

| Mechanism | What It Intercepts | How It Works | Root Required? |
|---|---|---|---|
| `child_process` spawning | Network latency, DNS, process lifecycle | Spawns isolated child processes with controlled timers, signals, and memory limits | No |
| `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` | Filesystem syscalls (`open`, `write`) | C shared library intercepts libc calls via `dlsym(RTLD_NEXT, ...)` | No |
| Environment variable pass-through | Injection configuration | Sets `INJECT_EACCES_PATH`, `INJECT_ENOSPC_PATH` on child env | No |
| DNS poison via unresolvable hosts | DNS resolution | Resolves guaranteed-nonexistent `.invalid` hostnames | No |

---

## 1. Process-Level Fault Injection (`fault-injection.js`)

All network, memory, and process faults are simulated by spawning isolated child processes through Node.js `child_process.spawn`. The child process is the fault target — it never affects the parent or the host system.

### Network Latency (`injectLatency`)

A child `node -e` process executes a `setTimeout` for the requested delay before exiting. The parent measures wall-clock elapsed time to verify the latency was injected. No traffic shaping or kernel queue is involved — the latency is injected at the process execution level.

```
Parent: spawn('node', ['-e', 'setTimeout(() => process.exit(0), 2000)'])
  → waits for 'close' event
  → measures elapsed ≥ 1800ms (90% of target)
```

### DNS Failure (`simulateDNSFailure` / `simulateDNSFailureViaProcess`)

Two approaches, both user-space:

1. **Direct Node.js DNS API**: Calls `dns.resolve4()` on a hostname under the `.invalid` TLD (e.g., `this-host-does-not-exist-chaos-test.invalid`). The `.invalid` TLD is reserved by RFC 2606 and guaranteed to never resolve — the system resolver returns `ENOTFOUND` / `ENODATA` without any network traffic.

2. **Via child process**: Spawns a child `node -e` that calls `dns.lookup()` on the same `.invalid` host. The child exits with code 1 on failure. This tests that CLI tools properly propagate DNS errors from subprocess invocations.

No `/etc/hosts` modifications. No DNS server manipulation.

### OOM Kill (`simulateOOMKill`)

A child process allocates memory in a loop (`Buffer.alloc(1MB)` per iteration) until the Node.js `--max-old-space-size` limit is hit, or until the parent sends `SIGKILL` after a timeout. The child exits with code 137 (killed by signal). This simulates the observable behavior of an OOM kill without requiring `cgroups` or kernel memory accounting.

### Process Kill (`simulateProcessKill`)

Spawns a child process running an idle loop (`setInterval(() => {}, 100)`), then sends a configurable signal (`SIGKILL`, `SIGTERM`, etc.) after a delay. The parent observes the signal delivery and exit code. This tests that CLI tools handle unexpected termination gracefully.

### Disk Pressure (`simulateDiskPressure`)

Spawns a child `node -e` process that writes a configurable number of bytes to a temporary file (`/tmp/nebula-disk-pressure-test.tmp`). On completion (or if the write fails due to disk full), the child cleans up the file and reports the actual bytes written. This simulates disk-full conditions by consuming available space in a controlled manner — no filesystem remounting or `dd if=/dev/zero` required.

---

## 2. Filesystem Syscall Interception via `LD_PRELOAD` (`fs_injector.c`)

The filesystem injector is a **compiled C shared library** (`fs_injector.so`) that uses the standard Linux `LD_PRELOAD` mechanism to intercept libc filesystem calls before they reach the kernel.

### How `LD_PRELOAD` Works

When the dynamic linker (`ld.so`) loads a program, it checks the `LD_PRELOAD` environment variable for a list of shared libraries to load **before** `libc`. Any symbol defined in a preloaded library takes priority over the `libc` version. This is a standard, well-documented POSIX feature — no special privileges required.

```
User sets: LD_PRELOAD=./fs_injector.so
  → ld.so loads fs_injector.so before libc
  → fs_injector.so defines open(), write(), etc.
  → Program calls open() → hits fs_injector.so version
  → fs_injector.so calls dlsym(RTLD_NEXT, "open") to get real libc version
```

### What the Injector Intercepts

The C library in `fs_injector.c` intercepts four libc functions:

| Function | Purpose | Injection |
|---|---|---|
| `open()` | File open | Returns `EACCES` if path matches `INJECT_EACCES_PATH` |
| `open64()` | Large-file open | Returns `EACCES` if path matches `INJECT_EACCES_PATH` |
| `openat()` | Relative-path open | Returns `EACCES` if path matches `INJECT_EACCES_PATH` |
| `write()` | Write to fd | Returns `ENOSPC` if fd points to a file matching `INJECT_ENOSPC_PATH` |

### Configuration via Environment Variables

The injector reads two environment variables to determine which paths to target:

- **`INJECT_EACCES_PATH`**: Substring to match against the `pathname` argument of `open`/`open64`/`openat`. If the path contains this string, the call returns `-1` with `errno = EACCES` (permission denied).
- **`INJECT_ENOSPC_PATH`**: Substring to match against the file path resolved from the file descriptor (via `/proc/self/fd/<fd>` symlink). If the fd points to a matching file, `write()` returns `-1` with `errno = ENOSPC` (no space left on device).

### The Wrapper (`fs-injector-wrapper.js`)

The JavaScript wrapper `runWithFsFaults()` handles the mechanics of launching a child process with the correct environment:

```js
const env = { ...process.env };
env.LD_PRELOAD = './fs_injector.so';
env.INJECT_EACCES_PATH = options.injectEaccesPath;  // e.g., 'test-file.txt'
env.INJECT_ENOSPC_PATH = options.injectEnospcPath;  // e.g., 'test-file.txt'

const child = spawn(command, args, { env, cwd: __dirname });
```

The child process (the CLI tool under test) inherits these environment variables. Its filesystem calls are transparently intercepted — the tool itself does not need to be aware of the injector.

### Why This Requires No Root

`LD_PRELOAD` is a per-process mechanism governed by the dynamic linker. Any user can set it for processes they own. The `.so` file is a normal shared library compiled with `gcc -shared -fPIC` — no `CAP_SYS_RAWIO`, no `CAP_NET_ADMIN`, no kernel capabilities of any kind.

---

## 3. Cross-Platform Capabilities and Limitations

### Linux (Primary Platform)

| Feature | Status | Notes |
|---|---|---|
| Process-level fault injection | Full | `child_process.spawn` works identically |
| `LD_PRELOAD` filesystem injector | Full | `LD_PRELOAD` is a native Linux/ELF feature |
| DNS fault simulation | Full | `.invalid` TLD handled by system resolver |
| OOM kill simulation | Full | `--max-old-space-size` + signal timeout |
| Process kill simulation | Full | `process.kill()` with any signal |

**All features are fully supported on Linux.**

### macOS

| Feature | Status | Notes |
|---|---|---|
| Process-level fault injection | Full | `child_process.spawn` works identically |
| `LD_PRELOAD` filesystem injector | Partial | macOS uses `DYLD_INSERT_LIBRARIES` + `DYLD_FORCE_FLAT_NAMESPACE=1` instead of `LD_PRELOAD`. System Integrity Protection (SIP) disables `DYLD_*` variables for system binaries, but user-compiled binaries (e.g., Node.js) work normally. The C code in `fs_injector.c` uses `_GNU_SOURCE` and `dlsym(RTLD_NEXT, ...)` which are available on macOS via `libdyld`. |
| DNS fault simulation | Full | `.invalid` TLD works on macOS resolver |
| OOM kill simulation | Full | Same Node.js mechanism |
| Process kill simulation | Full | Same signal mechanism |

**Caveat**: The `fs_injector.c` source uses `/proc/self/fd/<fd>` to resolve file descriptors to paths. macOS does not have `/proc`. To support macOS, the `write()` interception would need to use `fcntl(F_GETPATH)` instead. This is a known limitation; the primary filesystem injector currently targets Linux only.

### Windows

| Feature | Status | Notes |
|---|---|---|
| Process-level fault injection | Partial | `child_process.spawn` works, but signal semantics differ (`SIGKILL` = `process.kill()` with no signal, no `SIGTERM` equivalent) |
| `LD_PRELOAD` filesystem injector | Not supported | Windows has no `LD_PRELOAD`. Filesystem interception would require a DLL injected via `CreateRemoteThread` + `LoadLibrary` (the Detours pattern) or Windows minifilter drivers (kernel-mode, requires admin). |
| DNS fault simulation | Partial | Windows resolver does not respect `.invalid` TLD the same way; may require `nslookup`-based approach or hostfile manipulation |
| OOM kill simulation | Limited | No `--max-old-space-size` on Windows Node.js; would need `taskkill /F` |
| Process kill simulation | Limited | `process.kill()` on Windows sends `TerminateProcess`, no signal selection |

**Windows support is not currently implemented.** Process-level tests (concurrency, fuzz, stress) work if Node.js is available. Filesystem injection is not portable to Windows without significant rework.

---

## What This Is NOT

To be explicit about what `nebula-cli-chaos` does **not** use:

- **No `sudo` / root privileges** — every mechanism runs as the invoking user
- **No eBPF / BPF** — no kernel probes, no tracing, no `bcc` / `bpftrace`
- **No `tc netem`** — no traffic control queue manipulation for latency/loss
- **No kernel modules** — no `insmod`, no `/dev/` device nodes
- **No `iptables` / `nftables`** — no firewall rule manipulation
- **No `/etc/hosts` modification** — DNS faults use reserved TLDs, not hostfile edits
- **No `ptrace`** — no process tracing or debugging APIs
- **No Docker / containers required** — runs on bare metal or any environment with Node.js

---

## Component Interaction Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          nebula-chaos CLI                                   │
│                        (chaos-runner.js)                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                     ChaosTestRunner (test-runner.js)                        │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  exec() — spawns target CLI with controlled:                        │   │
│  │    • environment variables (LD_PRELOAD, INJECT_*)                   │   │
│  │    • stdin data                                                      │   │
│  │    • timeout / SIGKILL                                               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌───────────────────────────┐  ┌────────────────────────────────────────┐  │
│  │  FaultInjector            │  │  fs-injector-wrapper.js                │  │
│  │  (fault-injection.js)     │  │  Sets LD_PRELOAD + env vars           │  │
│  │                           │  │  and spawns target process             │  │
│  │  • injectLatency()        │  └──────────────┬─────────────────────────┘  │
│  │  • simulateDNSFailure()   │                 │                            │
│  │  • simulateDiskPressure() │                 ▼                            │
│  │  • simulateOOMKill()      │  ┌──────────────────────────────────────┐   │
│  │  • simulateProcessKill()  │  │  fs_injector.so (compiled C)         │   │
│  └───────────────────────────┘  │  LD_PRELOAD intercepts:              │   │
│                                  │    open(), open64(), openat()        │   │
│                                  │    write()                           │   │
│                                  │  Returns EACCES / ENOSPC based on   │   │
│                                  │  INJECT_EACCES_PATH / INJECT_ENOSPC │   │
│                                  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

- The `LD_PRELOAD` mechanism only affects child processes spawned with the preloaded library — it does not affect the parent `nebula-chaos` process or other system processes.
- Filesystem injection targets are controlled by environment variables scoped to the child process; they do not leak to other processes.
- The `fs_injector.so` library does not log, transmit, or persist any data — it is a pure syscall filter.
- All fault injection is reversible: removing the `LD_PRELOAD` variable or terminating the child process restores normal behavior.
