# Remote execution: shell vs. native Go

This note records why UBO drives the remote host with shell, where Go could
replace it, and the planned direction. It exists because "why not just upload
the binary and do everything in Go?" is a reasonable question with a non-obvious
answer.

## Current split

- **Local CLI (`ubo run/unlock/status`)** — pure Go. No local shell. The binary
  builds argv and `exec`s `wg`, `ssh`, `scp`, `wg-quick` directly.
- **Remote one-time setup (`ubo run`)** — Go orchestrates ~15 `ssh root@host
  '<cmd>'` round-trips: `apt-get`, `ip route`/`ip addr`, `dropbearkey`,
  `update-grub`, `update-initramfs`, plus file writes piped over `ssh`.
- **Remote boot-time** — a POSIX `/bin/sh` `init-premount/wireguard` script that
  runs inside the initramfs on every boot, before the disk is decrypted.

## What can and cannot move to Go

| Layer | Can it be Go? | Notes |
|-------|---------------|-------|
| Local CLI | Already Go | Nothing to do. |
| Remote one-time setup | Partially | Still must shell out to `apt`/`ip`/`update-grub`/`dropbearkey` — there is no Go API for these. Go would only own the glue/parsing. |
| Remote boot-time init-premount | **No** | initramfs-tools' contract is `/bin/sh` scripts with `PREREQ` headers slotted into the udev→premount→mount ordering graph. A Go binary cannot participate in that graph and would have to be invoked by a shell stub anyway. It would also bloat the unencrypted `/boot` image (the one that holds the WG key). |

UBO is an **operator tool**, not a server agent: it configures the box once from
your laptop and leaves no UBO process behind. The only persistent UBO-authored
artifact on the server is the tiny init-premount script. "Upload the binary and
let it reconfigure itself" is the daemon/agent model, which would add a listening
footprint and contradict the "only WireGuard is exposed" guarantee.

## Options considered

### Option A — Bundle remote setup into one uploaded script (recommended)
Render a single `setup.sh` from the existing templates, `scp` it up, run it once,
parse structured output. Replaces N `ssh '<cmd>'` round-trips with one atomic,
saved-as-artifact run.
- Pros: atomic, debuggable (script is kept), fewer round-trips, easier to audit.
- Cons: coarser per-step progress; still shell (by necessity — it calls system
  tools).
- Effort: medium. Risk: low. **This is the only option with a clear payoff.**

### Option B — Upload a static `ubo-remote` helper binary (Go on the server, setup only)
Cross-compile a static helper, `scp` it up, run `ubo-remote configure --json …`,
have it do network detection / grub edit / file writes in Go, then self-delete.
- Pros: real Go + unit tests for the grub-edit / network-parse logic currently
  embedded in `ssh` one-liners.
- Cons: still shells out to `apt`/`ip`/`update-grub`/`dropbearkey`; adds
  cross-compile + upload + cleanup; reintroduces a binary into the server
  footprint we deliberately keep minimal. Gain over A is mostly "Go error
  handling instead of shell."
- Effort: medium-high. Value: medium. **Not recommended now.**

### Option C — Keep the boot-time init-premount script as shell (required)
Not a choice: it is the initramfs-tools contract. Only ongoing work here is
hardening (audit items M1 boot-ordering, M2 fail-open `set -e`).

## Decision

Pursue **Option A** if/when remote setup robustness becomes a priority. Leave the
boot-time script as shell (Option C). Do not pursue Option B unless a concrete
need for Go-side remote logic appears.

## Recommended long-term end-state

The two layers have opposite constraints, so the clean answer is not "all Go" or
"all shell" — it is a single pattern UBO already uses for the WireGuard config:

> **Go owns logic, validation, and tests. Shell is a generated, typed-rendered
> output that only ever calls system tools. Nothing UBO-authored stays resident
> on the server except a minimal, generated boot script.**

Concretely:

1. **Boot-time (Layer 2):** stop hand-writing the init-premount script as a raw
   `const`; render it from a typed `BootScript` struct with a validated
   `Render() (string, error)`, mirroring `WireGuardServerConfig.MarshalINI()`.
   Correctness (incl. audit items M1 ordering / M2 fail-open) lives in Go with
   unit tests; the emitted `/bin/sh` stays tiny and auditable in `/boot`.
2. **One-time setup (Layer 1):** collapse the ~15 `ssh '<cmd>'` round-trips into
   **one idempotent `setup.sh`**, rendered from typed models, `scp`'d up, run
   once, with a structured (JSON) result parsed back in Go. Atomic, resumable,
   saved as an inspectable artifact.
3. **Never** ship a resident Go agent or a fat binary in the initramfs — both
   break the "only WireGuard is exposed / minimal secret-bearing /boot"
   guarantees.

This is an extension of the existing typed-render pattern, not a rewrite.
