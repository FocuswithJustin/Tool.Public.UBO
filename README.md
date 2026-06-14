# UBO — Unidentified Booting Object

Remotely unlock a LUKS-encrypted Debian system at boot, over an encrypted tunnel,
without ever exposing an SSH port to the internet.

UBO configures a headless Debian host so that when it reboots it halts in its
initramfs with the root disk still encrypted, brings up a WireGuard interface,
and runs a tiny Dropbear SSH server **bound only to the WireGuard tunnel**. From
your laptop you bring up the tunnel, SSH in, type the LUKS passphrase, and the
machine finishes booting. The disk passphrase is never stored anywhere and the
box is never reachable except through the VPN.

---

## Why

Full-disk encryption is great until the machine is in a closet, a colo, or a
datacenter and reboots at 3 a.m. — someone has to physically attend the console
to type the passphrase. The usual fix (Dropbear in the initramfs listening on
the public internet) trades one problem for another: a password-or-key SSH
service exposed to the whole world during early boot.

UBO's security model:

- **WireGuard is the only publicly exposed service.** It is silent to
  unauthenticated peers — no handshake, no response, nothing to scan.
- **Dropbear binds to the WireGuard tunnel IP only**, so the initramfs SSH
  server is unreachable unless your tunnel is already up and authenticated.
- **Key-only, hardened Dropbear**: no password auth, no port forwarding.
- **Host-key pinning (TOFU):** `ubo run` records the server's Dropbear host key;
  `ubo unlock` refuses to connect if it ever changes (MITM protection).
- **Initramfs secrets are root-only.** The boot image carries the WireGuard key
  (it must, to bring the tunnel up before decryption), so UBO generates it mode
  `0600` (`UMASK=0077`) — unreadable by unprivileged local users. See
  [Security notes](#security-notes) for the residual exposure.

---

## How it works

```
  your laptop                          remote server (encrypted, rebooting)
  ┌───────────┐                        ┌────────────────────────────────────┐
  │ ubo unlock│                        │ initramfs                          │
  │  wg-quick ├====== WireGuard ======>│  wg0  ──► Dropbear (tunnel IP only) │
  │  ssh -t   │     (only open port)   │            └─► cryptroot-unlock     │
  └───────────┘                        │  LUKS ──► LVM ──► / (still locked)  │
                                       └────────────────────────────────────┘
```

`ubo run` (executed from your machine, configuring the server over SSH):

1. Detects the server's network (interface / IP / gateway), or uses your config.
2. Installs `dropbear-initramfs` and `wireguard-tools`.
3. Generates a fresh Dropbear host key and pins its public key locally.
4. Writes a WireGuard server config consumed by `wg setconf` in the initramfs.
5. Installs an initramfs hook + init-premount script that loads the WireGuard
   module and brings up `wg0` early in boot.
6. Authorizes your client SSH key and hardens Dropbear's options.
7. Bakes static networking into `GRUB_CMDLINE_LINUX` (`ip=...`) and rebuilds the
   initramfs.

`ubo unlock` (later, when the server has rebooted and is waiting):

1. `wg-quick up` the generated client config (and always tears it down on exit).
2. Waits for the tunnel, then SSHes to Dropbear verifying the **pinned** host key.
3. Runs `cryptroot-unlock`, you enter the passphrase, the server boots on.

---

## Requirements

UBO itself is a single statically-linkable Go binary with **no external Go
dependencies** (standard library only); it drives `wg`, `ssh-keygen`, `ssh`,
`scp`, and `wg-quick` by shelling out to the system tools.

- **To run `ubo run`/`unlock` (your machine):** `wireguard-tools`, `openssh`.
- **`ubo unlock` needs root** (to bring the WireGuard interface up).
- **The remote host:** Debian 13 (Trixie) with a LUKS-encrypted root and an
  unencrypted `/boot`, reachable over SSH. The SSH user must have root privileges
  either directly (`user = "root"`) or via passwordless or interactive sudo
  (`sudo = true` in `[ssh]`).

A `shell.nix` is provided that pins Go and every tool used for building and
testing.

---

## Build

```sh
nix-shell --run "make build"     # produces ./ubo
# or, with the toolchain already on your PATH:
make build
```

---

## Quick start

```sh
# 1. Generate a starting config and edit it.
ubo init                      # writes ./ubo.toml
ubo configure                 # interactive TUI editor (or edit ubo.toml by hand)

# 2. Configure the remote host (generates keys, sets up the initramfs).
ubo run                       # uses ./ubo.toml; run as default subcommand too: `ubo`

# 3. Reboot the server. It will halt in the initramfs with the disk locked.

# 4. From your machine, unlock it (needs root for wg-quick).
sudo ubo unlock

# Optional: rotate the LUKS passphrase over the tunnel, then unlock.
sudo ubo unlock change
```

After `ubo run`, an output directory (default `./ubo-<host>/`) holds everything
the unlock step needs plus a `README.txt` with manual instructions.

---

## Subcommands

| Command          | What it does                                                                 |
|------------------|------------------------------------------------------------------------------|
| `ubo init`       | Write a default `ubo.toml` (non-interactive).                                 |
| `ubo configure`  | Open an interactive TUI to create or edit the config.                        |
| `ubo run`        | Configure the remote host. This is also the default when no subcommand given.|
| `ubo status`     | Report whether the output dir is configured and ready to unlock.            |
| `ubo unlock`     | Bring up WireGuard, SSH to Dropbear, run `cryptroot-unlock`, tear down.     |
| `ubo unlock change` | Change the LUKS passphrase via `cryptsetup luksChangeKey`, then optionally unlock. |

All subcommands accept `--config FILE` (default `./ubo.toml`).

---

## Configuration (`ubo.toml`)

```toml
# Remote host to configure
host = "192.168.1.100"

[ssh]
user = "root"
port = 22
key  = ""   # path to SSH private key; empty = use agent / default keys
sudo = false   # true = run setup via sudo (for non-root sudo-group users)

[wireguard]
port      = 51820
server_ip = "10.42.0.1/24"   # server WireGuard tunnel IP (CIDR)
client_ip = "10.42.0.2/32"   # client WireGuard tunnel IP (CIDR)

[dropbear]
port = 22

[output]
dir = ""   # empty = auto: ./ubo-<host>/

[network]
# Leave empty to auto-detect from the remote system's routing table
interface = ""
ip        = ""   # static IP/CIDR for initramfs (e.g. "192.168.1.100/24")

[luks]
device = ""   # LUKS block device (e.g. "/dev/sda3"); auto-detected from /etc/crypttab if empty
```

> The initramfs gets a *static* network configuration (DHCP isn't reliable that
> early). `ubo run` auto-detects the server's IP from the default route's `src`
> token; if that token is absent (common when the gateway is in-subnet), it falls
> back to `ip -4 addr show dev IFACE`. Set `network.ip` explicitly if both
> methods fail (e.g. `network.ip = "192.168.1.100/24"`).

> **Validation:** `wireguard.client_ip` must be distinct from
> `wireguard.server_ip` and fall within the server's tunnel subnet, and
> `luks.device` (when set) must be an absolute `/dev` path. `ubo run` and
> `ubo unlock` reject configs that violate these rules before touching the host.

---

## Output files

`ubo run` writes these into the output directory (private keys are mode `0600`,
the directory `0700`):

| File                       | Purpose                                                  |
|----------------------------|----------------------------------------------------------|
| `server_wg_private.key`    | WireGuard private key (deployed to the server).          |
| `server_wg_public.key`    | WireGuard public key.                                    |
| `client_wg_private.key`    | Your WireGuard private key — keep safe.                  |
| `client_wg_public.key`    | Your WireGuard public key.                               |
| `client_auth_ed25519`      | Your SSH private key for Dropbear — keep safe.           |
| `client_auth_ed25519.pub`  | SSH public key (deployed to the server's authorized_keys).|
| `dropbear_host_key.pub`    | Pinned Dropbear host key, verified on every `unlock`.    |
| `client_wg.conf`           | Ready-to-use WireGuard client config.                    |
| `README.txt`               | Step-by-step manual unlock instructions.                 |

---

## Development & testing

Everything runs inside `nix-shell` via `make`:

```sh
make build            # build ./ubo
make test             # unit tests
make vet              # go vet
make fmt              # gofmt -w .
make complexity       # fail if any function exceeds cyclomatic complexity 6
make check            # fmt + vet + complexity + unit tests (the full local gate)
```

### Integration tests (real VMs)

Integration tests run **entirely inside QEMU/KVM VMs** — UBO's privileged steps
(bringing up WireGuard, decrypting disks) are exercised for real, not mocked.
The full remote-unlock test boots two VMs linked by a userspace QEMU socket (no
host root, no TAP): a LUKS-encrypted **server** and a **client** that acts as
NAT router and operator, runs `ubo run`, reboots the server into the
Dropbear+WireGuard initramfs, and drives `ubo unlock` end-to-end.

```sh
make vm-build         # download the Debian cloud image, prepare tmp/ (once)
make luks-build       # build the LUKS-encrypted server image inside a builder VM (once)
make test-integration # boot the VMs and run the tagged integration tests
```

The build artifacts and all scratch files live in `tmp/` (gitignored).

---

## Project layout

```
main.go                     CLI dispatch and the run / unlock / status flows
internal/
  config/                   ubo.toml load/save, defaults, validation
  checker/                  local tool-availability checks
  keygen/                   WireGuard + SSH key generation (via wg / ssh-keygen)
  remote/                   SSH/SCP exec + host-key pinning
  setup/                    the 11 ordered remote configuration steps
  templates/                generated initramfs hooks, scripts, and configs
  tui/                      interactive config editor
tests/                      VM-based integration tests + image builders
```

---

## Security notes

- Treat the output directory as secret material — it contains the WireGuard and
  SSH private keys that can unlock the disk.
- Re-running `ubo run` is a full re-provision: it regenerates **all** keys
  (including the pinned Dropbear host key) consistently in the output directory.
- The LUKS passphrase is only ever typed interactively into the remote
  `cryptroot-unlock` prompt — UBO neither stores nor transmits it in any file.
- **The initramfs embeds the WireGuard server private key.** Because the tunnel
  must come up *before* the root disk is decrypted, that key necessarily lives
  in the unencrypted `/boot`. UBO writes `UMASK=0077` to
  `/etc/initramfs-tools/conf.d/ubo` so the generated image is mode `0600`
  (root-only): a local *unprivileged* user cannot extract the key with
  `lsinitramfs`/`unmkinitramfs`. It cannot be encrypted at rest (it is needed
  pre-decryption), so anyone with root on the server — or physical/offline
  access to the disk — can still read it. Compromise of this key lets an
  attacker impersonate the *initramfs WireGuard endpoint*; it does **not** by
  itself decrypt the disk (the LUKS passphrase is never stored).
- Inputs that flow into remote shell commands are validated: `luks.device` must
  be an absolute `/dev` path, and the detected interface, IP, gateway, and
  hostname baked into the GRUB `ip=` parameter are checked before use.
