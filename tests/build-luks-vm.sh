#!/usr/bin/env bash
# tests/build-luks-vm.sh — builds a LUKS-encrypted Debian 13 server image for the
# full remote-unlock integration test.
#
# The image is built ENTIRELY INSIDE A BUILDER VM (no host root required):
#   1. Boot the plain Debian cloud image (tmp/debian-trixie.qcow2) as a builder.
#   2. Attach a blank disk (tmp/debian-luks.qcow2) as the second virtio drive.
#   3. cloud-init runs a build script AS ROOT inside the builder that:
#        - partitions the blank disk: vdb1 = unencrypted /boot, vdb2 = LUKS
#        - LUKS-formats vdb2 with a KNOWN passphrase, opens it, makes an LVM VG
#          with a single root LV  (the Debian "guided encrypted LVM" layout)
#        - debootstraps Debian trixie onto it
#        - installs kernel + grub-pc + cryptsetup-initramfs + openssh-server
#        - injects the test SSH key, writes /etc/crypttab + /etc/fstab
#        - installs GRUB to the disk MBR with a serial console so the LUKS prompt
#          is reachable over ttyS0
#        - prints a sentinel line to the serial console and powers off
#   4. The host watches the serial log for the sentinel, then the image is ready.
#
# Requires (provided by nix-shell): qemu-img, qemu-system-x86_64, xorriso.
# Depends on tmp/debian-trixie.qcow2 + tmp/test_ed25519(.pub) from build-vm.sh.
#
# Output: tmp/debian-luks.qcow2 — a bootable LUKS-encrypted Debian server.
#
# The LUKS passphrase is a fixed, well-known test fixture (NOT a secret):
#   LUKS passphrase: ubotestphrase

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP="$ROOT_DIR/tmp"
mkdir -p "$TMP"

LUKS_IMAGE="$TMP/debian-luks.qcow2"
BUILDER_IMAGE="$TMP/debian-trixie.qcow2"
SSH_KEY="$TMP/test_ed25519"
LUKS_PASSPHRASE="ubotestphrase"
LUKS_SIZE="10G"

# ── 0. Preconditions ──────────────────────────────────────────────────────────
echo "==> Checking prerequisites..."
for tool in qemu-img qemu-system-x86_64 xorriso base64; do
    command -v "$tool" &>/dev/null || { echo "ERROR: missing tool: $tool (run nix-shell)"; exit 1; }
done
for f in "$BUILDER_IMAGE" "$SSH_KEY" "$SSH_KEY.pub"; do
    [ -f "$f" ] || { echo "ERROR: missing $f — run 'make vm-build' first."; exit 1; }
done

if [ -f "$LUKS_IMAGE" ]; then
    echo "==> $LUKS_IMAGE already exists; remove it to rebuild. Done."
    exit 0
fi

SSH_PUB_KEY=$(cat "$SSH_KEY.pub")

# ── 1. Create the blank target disk ──────────────────────────────────────────
echo "==> Creating blank LUKS target disk ($LUKS_SIZE)..."
qemu-img create -f qcow2 "$LUKS_IMAGE.tmp" "$LUKS_SIZE" >/dev/null

# ── 2. Render the in-guest build script (placeholders substituted on host) ────
SEED_TMP="$(mktemp -d)"
trap 'rm -rf "$SEED_TMP"' EXIT

# Quoted heredoc: NOTHING here is expanded on the host. Guest-time shell
# variables ($PASS, $TARGET, ...) survive verbatim. Host values are injected via
# the @@PLACEHOLDER@@ tokens substituted immediately after.
cat > "$SEED_TMP/build-luks.sh" <<'BUILD_EOF'
#!/bin/bash
set -euo pipefail
exec > >(tee /dev/console) 2>&1
echo "LUKS_BUILD_START"

PASS='@@PASS@@'
SSHPUB='@@SSHPUB@@'
BOOTDEV=/dev/vdb1
LUKSDEV=/dev/vdb2
TARGET=/mnt/luks
MIRROR=http://deb.debian.org/debian
SUITE=trixie

echo "==> installing build tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y debootstrap cryptsetup-bin lvm2 parted dosfstools

echo "==> partitioning /dev/vdb (msdos: boot + luks)"
parted -s /dev/vdb mklabel msdos
parted -s /dev/vdb mkpart primary ext4 1MiB 768MiB
parted -s /dev/vdb set 1 boot on
parted -s /dev/vdb mkpart primary 768MiB 100%
udevadm settle || true
sleep 1

echo "==> LUKS formatting $LUKSDEV"
printf '%s' "$PASS" | cryptsetup luksFormat --type luks2 --batch-mode "$LUKSDEV" -
printf '%s' "$PASS" | cryptsetup luksOpen "$LUKSDEV" cryptroot -
LUKS_UUID=$(cryptsetup luksUUID "$LUKSDEV")
echo "==> LUKS UUID=$LUKS_UUID"

echo "==> LVM on mapped device"
pvcreate -ff -y /dev/mapper/cryptroot
vgcreate vg0 /dev/mapper/cryptroot
lvcreate -y -l 100%FREE -n root vg0

echo "==> filesystems"
mkfs.ext4 -q -L bootfs "$BOOTDEV"
mkfs.ext4 -q -L rootfs /dev/mapper/vg0-root
BOOT_UUID=$(blkid -s UUID -o value "$BOOTDEV")

echo "==> mounting"
mkdir -p "$TARGET"
mount /dev/mapper/vg0-root "$TARGET"
mkdir -p "$TARGET/boot"
mount "$BOOTDEV" "$TARGET/boot"

echo "==> debootstrap $SUITE (this takes a few minutes)"
debootstrap --include=linux-image-amd64,grub-pc,cryptsetup,cryptsetup-initramfs,lvm2,openssh-server,ifupdown,isc-dhcp-client,locales \
  "$SUITE" "$TARGET" "$MIRROR"

echo "==> base system config"
echo "ubo-luks-server" > "$TARGET/etc/hostname"
cat > "$TARGET/etc/hosts" <<HOSTS
127.0.0.1 localhost
127.0.1.1 ubo-luks-server
HOSTS

cat > "$TARGET/etc/fstab" <<FSTAB
/dev/mapper/vg0-root / ext4 errors=remount-ro 0 1
UUID=$BOOT_UUID /boot ext4 defaults 0 2
FSTAB

cat > "$TARGET/etc/crypttab" <<CRYPTTAB
cryptroot UUID=$LUKS_UUID none luks
CRYPTTAB

# DHCP on the first ethernet iface (matches QEMU user networking used during
# 'ubo run'); covers common virtio names.
cat > "$TARGET/etc/network/interfaces" <<NETIF
auto lo
iface lo inet loopback
allow-hotplug ens3
iface ens3 inet dhcp
allow-hotplug enp0s3
iface enp0s3 inet dhcp
allow-hotplug eth0
iface eth0 inet dhcp
NETIF

mkdir -p "$TARGET/root/.ssh"
chmod 700 "$TARGET/root/.ssh"
echo "$SSHPUB" > "$TARGET/root/.ssh/authorized_keys"
chmod 600 "$TARGET/root/.ssh/authorized_keys"

# serial console so the LUKS prompt + boot are reachable over ttyS0
cat > "$TARGET/etc/default/grub" <<GRUBCFG
GRUB_DEFAULT=0
GRUB_TIMEOUT=2
GRUB_DISTRIBUTOR=Debian
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200"
GRUB_TERMINAL="serial console"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"
GRUB_ENABLE_CRYPTODISK=n
GRUBCFG

echo "==> chroot: grub + initramfs + ssh"
mount --bind /dev "$TARGET/dev"
mount --bind /dev/pts "$TARGET/dev/pts"
mount --bind /proc "$TARGET/proc"
mount --bind /sys "$TARGET/sys"
cp /etc/resolv.conf "$TARGET/etc/resolv.conf"

chroot "$TARGET" /bin/bash -eux <<CHROOT
export DEBIAN_FRONTEND=noninteractive
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl enable ssh || true
systemctl enable serial-getty@ttyS0.service || true
update-initramfs -u -k all
grub-install --target=i386-pc /dev/vdb
update-grub
echo 'root:ubotestroot' | chpasswd
CHROOT

echo "==> unmounting"
sync
umount "$TARGET/dev/pts" || true
umount "$TARGET/dev" || true
umount "$TARGET/proc" || true
umount "$TARGET/sys" || true
umount "$TARGET/boot" || true
umount "$TARGET" || true
vgchange -an vg0 || true
cryptsetup luksClose cryptroot || true

echo "LUKS_BUILD_OK"
BUILD_EOF

# Substitute host values using bash parameter expansion (literal, not regex —
# safe with the '/' '+' '=' characters in an SSH public key).
_script=$(cat "$SEED_TMP/build-luks.sh")
_script=${_script//@@PASS@@/$LUKS_PASSPHRASE}
_script=${_script//@@SSHPUB@@/$SSH_PUB_KEY}
printf '%s' "$_script" > "$SEED_TMP/build-luks.sh"
unset _script

BUILD_B64=$(base64 -w0 "$SEED_TMP/build-luks.sh")

# ── 3. cloud-init seed (script injected base64 — no YAML indentation hazards) ──
cat > "$SEED_TMP/meta-data" <<'EOF'
instance-id: ubo-luks-builder-001
local-hostname: ubo-luks-builder
EOF

cat > "$SEED_TMP/user-data" <<EOF
#cloud-config
hostname: ubo-luks-builder
disable_root: false
ssh_pwauth: false

write_files:
  - path: /root/build-luks.sh
    permissions: '0755'
    encoding: b64
    content: ${BUILD_B64}

runcmd:
  - bash -c '/root/build-luks.sh || echo LUKS_BUILD_FAIL > /dev/console; sleep 2; poweroff'
EOF

SEED_ISO="$TMP/luks-build-seed.iso"
echo "==> Creating build seed ISO..."
xorriso -as mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock \
    -input-charset utf-8 "$SEED_TMP/user-data" "$SEED_TMP/meta-data" 2>/dev/null

# ── 4. Boot the builder VM ───────────────────────────────────────────────────
SERIAL_LOG="$TMP/luks-build-serial.log"
: > "$SERIAL_LOG"
echo "==> Booting builder VM (debootstrap inside guest, several minutes)..."

QEMU_ARGS=(
    -m 2048
    -smp 2
    -nographic
    -drive "file=$BUILDER_IMAGE,format=qcow2,if=virtio,snapshot=on"
    -drive "file=$LUKS_IMAGE.tmp,format=qcow2,if=virtio"
    -drive "file=$SEED_ISO,format=raw,if=virtio,media=cdrom,readonly=on"
    -netdev "user,id=net0"
    -device virtio-net-pci,netdev=net0
    -serial "file:$SERIAL_LOG"
)
if [ -e /dev/kvm ]; then
    QEMU_ARGS=(-enable-kvm -cpu host "${QEMU_ARGS[@]}")
fi

qemu-system-x86_64 "${QEMU_ARGS[@]}" &
QEMU_PID=$!
trap 'kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -rf "$SEED_TMP"' EXIT

echo "==> Waiting for build to finish (watching $SERIAL_LOG, up to 25 min)..."
TIMEOUT=1500
ELAPSED=0
RESULT=""
while [ $ELAPSED -lt $TIMEOUT ]; do
    if grep -q "LUKS_BUILD_OK" "$SERIAL_LOG" 2>/dev/null; then
        RESULT="ok"; break
    fi
    if grep -q "LUKS_BUILD_FAIL" "$SERIAL_LOG" 2>/dev/null; then
        RESULT="fail"; break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        grep -q "LUKS_BUILD_OK" "$SERIAL_LOG" && RESULT="ok" || RESULT="fail"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

# Allow the VM to power off cleanly, then ensure it's gone.
for _ in 1 2 3 4 5 6; do
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 5
done
kill "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
trap 'rm -rf "$SEED_TMP"' EXIT

if [ "$RESULT" != "ok" ]; then
    echo ""
    echo "ERROR: LUKS image build did not succeed (result='${RESULT:-timeout}')."
    echo "Last 40 lines of $SERIAL_LOG:"
    tail -n 40 "$SERIAL_LOG" 2>/dev/null || true
    rm -f "$LUKS_IMAGE.tmp"
    exit 1
fi

mv "$LUKS_IMAGE.tmp" "$LUKS_IMAGE"
echo ""
echo "==> LUKS server image built: $LUKS_IMAGE"
echo "    LUKS passphrase: $LUKS_PASSPHRASE"
echo "    root password (serial console): ubotestroot"
