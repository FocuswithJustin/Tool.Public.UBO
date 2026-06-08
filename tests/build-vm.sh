#!/usr/bin/env bash
# tests/build-vm.sh — builds the Debian 13 QEMU test VM for integration testing.
#
# Requires (provided by nix-shell): qemu-img, qemu-system-x86_64, wget, xorriso, ssh-keygen
#
# Output (all in tmp/):
#   tmp/debian-trixie.qcow2   — base Debian 13 cloud image (8G)
#   tmp/seed.iso              — cloud-init seed ISO (SSH key injection)
#   tmp/test_ed25519          — test SSH private key
#   tmp/test_ed25519.pub      — test SSH public key
#
# The VM is booted once to verify SSH access, then shut down.
# Subsequent test runs use snapshot=on so the base image is never modified.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP="$ROOT_DIR/tmp"
mkdir -p "$TMP"

# ── 1. Generate test SSH key ──────────────────────────────────────────────────
SSH_KEY="$TMP/test_ed25519"
if [ ! -f "$SSH_KEY" ]; then
    echo "==> Generating integration test SSH keypair..."
    ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "ubo-integration-test" -q
    chmod 600 "$SSH_KEY"
fi
SSH_PUB_KEY=$(cat "$SSH_KEY.pub")

# ── 2. Download Debian 13 cloud image ────────────────────────────────────────
IMAGE="$TMP/debian-trixie.qcow2"
if [ ! -f "$IMAGE" ]; then
    echo "==> Downloading Debian 13 (Trixie) genericcloud image..."
    URLS=(
        "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
        "https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-genericcloud-amd64.qcow2"
    )
    downloaded=false
    for url in "${URLS[@]}"; do
        echo "  Trying $url ..."
        if wget -q --show-progress -O "$IMAGE.tmp" "$url"; then
            mv "$IMAGE.tmp" "$IMAGE"
            downloaded=true
            break
        fi
        rm -f "$IMAGE.tmp"
    done
    if [ "$downloaded" = "false" ]; then
        echo ""
        echo "ERROR: Could not download Debian 13 cloud image."
        echo "Download manually and place at: $IMAGE"
        echo "  wget -O '$IMAGE' https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
        exit 1
    fi
    echo "==> Resizing to 8G..."
    qemu-img resize "$IMAGE" 8G
fi

# ── 3. Create cloud-init seed ISO ────────────────────────────────────────────
SEED_ISO="$TMP/seed.iso"
SEED_TMP="$(mktemp -d)"
trap 'rm -rf "$SEED_TMP"' EXIT

cat > "$SEED_TMP/meta-data" <<'EOF'
instance-id: debian-ubo-test-001
local-hostname: debian-ubo-test
EOF

cat > "$SEED_TMP/user-data" <<EOF
#cloud-config
hostname: debian-ubo-test
fqdn: debian-ubo-test.local

disable_root: false
ssh_pwauth: false

users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $SSH_PUB_KEY

write_files:
  - path: /etc/ssh/sshd_config.d/99-ubo-test.conf
    content: |
      PermitRootLogin prohibit-password
      PasswordAuthentication no
    permissions: '0644'

runcmd:
  - systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
EOF

echo "==> Creating cloud-init seed ISO..."
xorriso -as mkisofs \
    -output "$SEED_ISO" \
    -volid cidata \
    -joliet \
    -rock \
    -input-charset utf-8 \
    "$SEED_TMP/user-data" \
    "$SEED_TMP/meta-data" \
    2>/dev/null

# ── 4. Smoke-test: boot the VM and verify SSH access ─────────────────────────
echo "==> Booting VM for SSH smoke-test (this may take a few minutes)..."
SERIAL_LOG="$TMP/build-vm-serial.log"

QEMU_ARGS=(
    -m 1024
    -nographic
    -drive "file=$IMAGE,format=qcow2,if=virtio,snapshot=on"
    -drive "file=$SEED_ISO,format=raw,if=virtio,media=cdrom,readonly=on"
    -netdev "user,id=net0,hostfwd=tcp::2299-:22"
    -device virtio-net-pci,netdev=net0
    -serial "file:$SERIAL_LOG"
)

if [ -e /dev/kvm ]; then
    QEMU_ARGS=(-enable-kvm -cpu host "${QEMU_ARGS[@]}")
fi

qemu-system-x86_64 "${QEMU_ARGS[@]}" &
QEMU_PID=$!
trap 'kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -rf "$SEED_TMP"' EXIT

echo "==> Waiting for SSH on port 2299 (up to 10 minutes)..."
TIMEOUT=600
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if ssh -i "$SSH_KEY" \
           -p 2299 \
           -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=5 \
           -o BatchMode=yes \
           root@127.0.0.1 \
           "echo ssh-ok" 2>/dev/null | grep -q "ssh-ok"; then
        echo "==> SSH access confirmed."
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ERROR: VM did not become reachable via SSH within $TIMEOUT seconds."
    echo "Check $SERIAL_LOG for boot errors."
    exit 1
fi

kill "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
trap 'rm -rf "$SEED_TMP"' EXIT   # reset trap to only clean SEED_TMP

echo ""
echo "==> VM build complete!"
echo "    Image:   $IMAGE"
echo "    Seed:    $SEED_ISO"
echo "    SSH key: $SSH_KEY"
echo ""
echo "Run 'make test-integration' to run the integration tests."
