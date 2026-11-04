# memsentry

**Detection tooling for memory-resident Linux tradecraft.**

[![Tests](https://img.shields.io/badge/tests-47%20passing-brightgreen?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)]()
[![Platform](https://img.shields.io/badge/platform-linux%20x86__64-informational?style=flat-square)]()
[![MSRV](https://img.shields.io/badge/rust-1.82%2B-orange?style=flat-square)]()

`memsentry` inspects running processes for the artefacts that memory-resident
implants leave behind: dormant encrypted regions, fileless execution, process
masquerading, and scrubbed command lines. It reads `/proc` directly through a
no-libc syscall layer, so the values it reports are exactly what the kernel
holds.

---

## Why this exists

Memory-resident malware is defined by what it *avoids* leaving on disk. That
removes the usual evidence — no dropped binary, no file hash, no filesystem
timeline — and pushes detection into process memory and kernel bookkeeping.

Those artefacts are observable, but they are not surfaced by standard tooling.
`ps` will happily show you a process whose name is `kworker/u16:1` and not tell
you that a kernel worker cannot have a userspace executable. `top` will show
you a normal-looking memory footprint and not tell you that 4 MB of it is
`PROT_NONE` and filled with 8.0 bits/byte of entropy.

`memsentry` looks for those specific inconsistencies.

---

## What it detects

| Detector | Signal | Rationale |
| :--- | :--- | :--- |
| **Dormant regions** | Anonymous mapping marked `---p`, multi-page | Ordinary processes rarely `PROT_NONE` a large anonymous region; it is how sleep-obfuscated state is parked |
| **Entropy anomaly** | Writable anonymous region, Shannon entropy > 7.5 bits/byte | A heap region holding near-uniform bytes is more likely ciphertext than data |
| **Fileless execution** | `/proc/<pid>/exe` resolves to `memfd:` | The image has no backing file on disk |
| **Deleted executable mapping** | Executable mapping backed by a `(deleted)` path | The binary was unlinked after it started |
| **Masquerade** | `comm` matches a kernel-thread pattern but the process has a userspace `exe` | Kernel workers have no userspace binary; this is the tell |
| **Scrubbed command line** | Empty `argv` on a non-kernel-thread | Legitimate processes keep their arguments |
| **RWX anonymous region** | Anonymous mapping that is writable *and* executable | Staged code that was not mapped from a file |

Each detector is a rule over kernel-visible state. None of them requires
modifying the target, and none of them requires root for the checks that read
world-readable `/proc` metadata.

---

## Architecture

```
                          +---------------------------------------+
                          |            memsentry CLI              |
                          |   scan | report | json output         |
                          +---------------------------------------+
                                            |
                          +---------------------------------------+
                          |             procscan                  |
                          |   /proc parsing and region analysis   |
                          |   - maps  - stat  - status  - cmdline |
                          |   - exe   - mem   - sealing           |
                          +---------------------------------------+
                                            |
                          +---------------------------------------+
                          |            raw-syscall                |
                          |   no-libc x86_64 syscall primitives   |
                          |   - syscall0..6  - constants          |
                          |   - exact errno, no stdlib shims      |
                          +---------------------------------------+
```

The layering is deliberate: the detector's correctness depends on reading
kernel state exactly, so the bottom layer returns raw kernel values and makes
no policy decisions.

---

## Design principles

**Report evidence, not verdicts.** Every finding is a statement about
observable state (`region 0x7f.. is 8.02 bits/byte and PROT_NONE`), not an
accusation. An operator or analyst decides what it means.

**Every detector is testable.** Each rule ships with a test that constructs the
condition it looks for and asserts the detector fires — and a test that
constructs a benign lookalike and asserts it does not. A detector you cannot
falsify is a liability.

**Read-only by default.** Inspection does not require modifying the target.
Where a check needs privilege (`/proc/<pid>/mem`), it degrades gracefully and
reports what it could not read rather than guessing.

**State the limits.** See [Scope](#scope-and-limitations).

---

## Workspace

```
memsentry/
├── crates/
│   ├── raw-syscall/    # no-libc x86_64 syscall primitives  (complete)
│   ├── procscan/       # /proc parsing + region analysis    (in progress)
│   └── memsentry/      # detection rules + CLI              (planned)
├── .github/workflows/  # CI: fmt, clippy, test
└── README.md
```

---

## Status

| Component | State | Tests |
| :--- | :--- | ---: |
| `raw-syscall` | Complete | 7 |
| `procscan` | Complete | 40 |
| `memsentry` detectors | Planned | — |

Current verification:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets   # zero warnings
cargo test --workspace                   # 47 passing
```

### A finding worth stating

Building `procscan` surfaced an assumption that the detector design depended
on. A mapping demoted to `PROT_NONE` is **still readable by the process that
owns it**: the kernel's `FOLL_FORCE` behaviour makes `/proc/self/mem` return
the real contents of a parked page rather than faulting.

The consequence is that access state cannot be treated as evidence. "The pages
are parked" does not mean "the contents are hidden", and a parked region can
still hold plaintext. The detector therefore ranks regions by *content* —
entropy, marker search — and uses protection state only to narrow the search.
The behaviour is pinned by `crates/procscan/tests/memory_access.rs` so a kernel
change that alters it shows up as a test failure rather than a silent
regression.

---

## Scope and limitations

- **Linux x86_64 only.** The syscall ABI and `/proc` layout are
  architecture-specific; nothing else is claimed.
- **Detection, not prevention.** `memsentry` observes; it does not block,
  quarantine, or modify a target process.
- **Not a rootkit detector.** Kernel-space concealment (module hiding, syscall
  table patching, eBPF-based evasion) is out of scope. `memsentry` reads the
  kernel's own bookkeeping, so it sees what that bookkeeping says — a kernel
  that lies will fool it.
- **Entropy is a heuristic.** Compressed data, encrypted files held in memory,
  and some media buffers are also high-entropy. The entropy detector reports a
  ranking signal, not proof.
- **Races are inherent.** A process can change between the `/proc` reads that
  build one finding. Findings carry the raw values that produced them so a
  reader can judge staleness.

---

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option.
