# shellcheck shell=bash
# QEMU virtual-machine helpers shared by the local test script and CI.
#
# One VM = one Ubuntu cloud image booted under QEMU with TWO network cards:
#
#   mgmt0  QEMU user-mode networking with a host-forwarded SSH port. Used only
#          to copy files in and run commands. XDP is never attached here, so the
#          control channel can never be cut by the filter under test.
#   test0  A NIC wired to a QEMU "stream" socket backend (a localhost TCP port).
#          Whatever the host writes to that socket arrives as an Ethernet frame
#          on test0, and the bladerunner XDP program attaches to this NIC. This
#          needs no root, no TAP device and no bridge on the host.
#
# Requires common.sh. Typical use:
#
#   vm_arch_init x86_64 1 "$workdir"
#   vm_prepare
#   vm_start
#   vm_wait_ready
#   vm_ssh uname -a
#   vm_stop

[ -n "${_BR_VM_SH:-}" ] && return 0
_BR_VM_SH=1

# Ubuntu release whose cloud images are used for every architecture.
VM_RELEASE=${VM_RELEASE:-noble}
VM_IMG_BASE=${VM_IMG_BASE:-https://cloud-images.ubuntu.com/$VM_RELEASE/current}
VM_CACHE=${VMTEST_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/bladerunner-vmtest}
VM_USER=ubuntu

# First address of the test subnet; each VM gets .1x on 10.77.0.0/24.
VM_SUBNET=10.77.0

# vm_arch_init ARCH INDEX WORKDIR
# Sets every VM_* variable the other functions use. ARCH is x86_64, aarch64 or
# riscv64 (the names `uname -m` prints, except riscv64 which is already that).
vm_arch_init() {
  VM_ARCH=$1; VM_IDX=$2; VM_DIR=$3/$1
  mkdir -p "$VM_DIR"
  local host; host=$(uname -m)

  # Per-arch settings: Go and Ubuntu architecture names, QEMU binary, memory
  # and the timeout (seconds) to wait for the guest to come up under emulation.
  # shellcheck disable=SC2034  # VM_GOARCH is read by scripts/vmtest.sh
  case $VM_ARCH in
    x86_64)  VM_GOARCH=amd64;   VM_UBU=amd64;   VM_QEMU=qemu-system-x86_64;   VM_BOOT_TIMEOUT=240 ;;
    aarch64) VM_GOARCH=arm64;   VM_UBU=arm64;   VM_QEMU=qemu-system-aarch64;  VM_BOOT_TIMEOUT=900 ;;
    riscv64) VM_GOARCH=riscv64; VM_UBU=riscv64; VM_QEMU=qemu-system-riscv64;  VM_BOOT_TIMEOUT=1500 ;;
    *) die "unknown architecture '$VM_ARCH' (use x86_64, aarch64 or riscv64)" ;;
  esac
  VM_MEM=${VMTEST_MEM:-2048}
  VM_SMP=${VMTEST_SMP:-2}

  # Hardware acceleration only when guest and host CPU match and KVM is usable;
  # otherwise QEMU emulates every instruction (TCG), which is much slower. The
  # test scales its traffic rates down when VM_SLOW=1.
  VM_SLOW=1
  if [ "$host" = "$VM_ARCH" ] && [ -w /dev/kvm ]; then VM_SLOW=0; fi
  if [ "$VM_SLOW" = 1 ] && [ "$VM_ARCH" = x86_64 ]; then VM_BOOT_TIMEOUT=900; fi

  # Stable identities: MACs the host knows in advance (the injector addresses
  # frames to VM_MAC_TEST) and the static IP on the test subnet.
  local n; n=$(printf '%02x' "$VM_IDX")
  VM_MAC_MGMT="52:54:00:aa:$n:01"
  VM_MAC_TEST="52:54:00:bb:$n:01"
  VM_TEST_IP="$VM_SUBNET.1$VM_IDX"
  VM_SSH_PORT=$(free_port)
  VM_NET_PORT=$(free_port)
  VM_KEY=$VM_DIR/id_ed25519
  VM_PIDFILE=$VM_DIR/qemu.pid
  VM_CONSOLE=$VM_DIR/console.log
  VM_SSH_OPTS=(-i "$VM_KEY" -p "$VM_SSH_PORT" -o IdentitiesOnly=yes
               -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
               -o LogLevel=ERROR -o ConnectTimeout=5 -o ServerAliveInterval=15)
  VM_SCP_OPTS=(-i "$VM_KEY" -P "$VM_SSH_PORT" -o IdentitiesOnly=yes
               -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
}

# ---- image ------------------------------------------------------------------

# vm_fetch_base: download the cloud image into the cache and verify it against
# the SHA256SUMS file Ubuntu publishes next to it. Prints nothing; sets VM_BASE.
vm_fetch_base() {
  mkdir -p "$VM_CACHE"
  local name=$VM_RELEASE-server-cloudimg-$VM_UBU.img sums want have
  sums=$(curl -fsSL "$VM_IMG_BASE/SHA256SUMS") || die "cannot fetch $VM_IMG_BASE/SHA256SUMS"
  want=$(printf '%s\n' "$sums" | awk -v n="*$name" '$2==n{print $1}')
  [ -n "$want" ] || die "no checksum for $name in SHA256SUMS"
  # Cache key includes the checksum, so a refreshed upstream image is fetched anew.
  VM_BASE=$VM_CACHE/$VM_RELEASE-$VM_UBU-${want:0:12}.img
  if [ -f "$VM_BASE" ]; then log "$VM_ARCH: using cached image $(basename "$VM_BASE")"; return 0; fi
  log "$VM_ARCH: downloading $name"
  curl -fL --retry 3 -C - ${VM_QUIET:+-sS} -o "$VM_BASE.part" "$VM_IMG_BASE/$name" || die "download failed"
  have=$(sha256sum "$VM_BASE.part" | awk '{print $1}')
  [ "$have" = "$want" ] || { rm -f "$VM_BASE.part"; die "checksum mismatch for $name"; }
  mv "$VM_BASE.part" "$VM_BASE"
}

# vm_make_seed: build the cloud-init "NoCloud" ISO. It installs the throw-away
# SSH key and configures both NICs by MAC address (and gives them fixed names).
vm_make_seed() {
  local d=$VM_DIR/seed; mkdir -p "$d"
  ssh-keygen -q -t ed25519 -N '' -C bladerunner-vmtest -f "$VM_KEY" <<<y >/dev/null
  cat > "$d/user-data" <<EOF
#cloud-config
ssh_pwauth: false
ssh_authorized_keys:
  - $(cat "$VM_KEY.pub")
package_update: false
package_upgrade: false
EOF
  cat > "$d/meta-data" <<EOF
instance-id: bladerunner-$VM_ARCH-$$
local-hostname: bladerunner-$VM_ARCH
EOF
  cat > "$d/network-config" <<EOF
version: 2
ethernets:
  mgmt0:
    match: {macaddress: "$VM_MAC_MGMT"}
    set-name: mgmt0
    dhcp4: true
  test0:
    match: {macaddress: "$VM_MAC_TEST"}
    set-name: test0
    dhcp4: false
    optional: true
    addresses: [$VM_TEST_IP/24]
EOF
  local mk
  for mk in genisoimage mkisofs xorriso; do command -v $mk >/dev/null && break; done
  case $mk in
    xorriso) xorriso -as mkisofs -quiet -output "$VM_DIR/seed.iso" -volid cidata -joliet -rock "$d" ;;
    genisoimage|mkisofs) $mk -quiet -output "$VM_DIR/seed.iso" -volid cidata -joliet -rock "$d" ;;
    *) die "need genisoimage, mkisofs or xorriso to build the cloud-init seed" ;;
  esac
}

# vm_prepare: fetch the base image, create a copy-on-write overlay (the cached
# base is never modified) and build the seed ISO.
vm_prepare() {
  need "$VM_QEMU" qemu-img curl ssh ssh-keygen sha256sum python3
  vm_fetch_base
  VM_DISK=$VM_DIR/disk.qcow2
  qemu-img create -q -f qcow2 -F qcow2 -b "$VM_BASE" "$VM_DISK" 8G
  vm_make_seed
}

# ---- firmware ---------------------------------------------------------------

# _first_file PATH...: print the first path that exists.
_first_file() { local f; for f in "$@"; do [ -f "$f" ] && { printf '%s' "$f"; return 0; }; done; return 1; }

# _vm_arch_args: print the architecture-specific QEMU arguments, one per line.
_vm_arch_args() {
  case $VM_ARCH in
    x86_64)
      # SeaBIOS (QEMU's default) boots the x86 cloud image; no firmware file needed.
      printf '%s\n' -machine q35 -accel kvm -accel tcg -cpu max ;;
    aarch64)
      local fw
      fw=$(_first_file /usr/share/AAVMF/AAVMF_CODE.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
                       /usr/share/edk2/aarch64/QEMU_EFI.fd /usr/share/edk2/aarch64/QEMU_CODE.fd) \
        || die "no aarch64 UEFI firmware found (Debian/Ubuntu: apt install qemu-efi-aarch64)"
      printf '%s\n' -machine virt -cpu max -bios "$fw"
      if [ "$VM_SLOW" = 0 ]; then printf '%s\n' -accel kvm; else printf '%s\n' -accel tcg; fi ;;
    riscv64)
      local ub
      printf '%s\n' -machine virt -cpu rv64 -accel tcg
      # Preferred: U-Boot as an S-mode payload on QEMU's built-in OpenSBI (what
      # Ubuntu documents for its riscv64 images).
      if ub=$(_first_file /usr/lib/u-boot/qemu-riscv64_smode/uboot.elf \
                          /usr/share/u-boot/qemu-riscv64_smode/uboot.elf); then
        printf '%s\n' -kernel "$ub"
      else
        # Fallback: EDK2 UEFI as pflash. The flash files must be exactly 32 MiB.
        local code vars
        code=$(_first_file /usr/share/edk2/riscv64/RISCV_VIRT_CODE.fd /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd) \
          || die "no riscv64 firmware found (Debian/Ubuntu: apt install u-boot-qemu)"
        vars=$(_first_file /usr/share/edk2/riscv64/RISCV_VIRT_VARS.fd /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd) \
          || die "no riscv64 UEFI vars template found"
        cp "$code" "$VM_DIR/code.fd"; cp "$vars" "$VM_DIR/vars.fd"
        truncate -s 32M "$VM_DIR/code.fd" "$VM_DIR/vars.fd"
        printf '%s\n' -drive "if=pflash,format=raw,unit=0,readonly=on,file=$VM_DIR/code.fd" \
                      -drive "if=pflash,format=raw,unit=1,file=$VM_DIR/vars.fd"
      fi ;;
  esac
}

# ---- lifecycle --------------------------------------------------------------

# vm_start: boot the VM in the background. QEMU daemonises itself and writes a
# pidfile; the serial console goes to $VM_CONSOLE for post-mortems.
vm_start() {
  local args=()
  mapfile -t args < <(_vm_arch_args)
  # The test NIC turns off guest offloads so that, if requested, native XDP can
  # attach to virtio-net (it refuses while LRO/checksum offload is negotiated).
  local testnic="virtio-net-pci,netdev=t0,mac=$VM_MAC_TEST,csum=off,guest_csum=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off"
  log "$VM_ARCH: starting VM (ssh :$VM_SSH_PORT, test link :$VM_NET_PORT, slow=$VM_SLOW)"
  "$VM_QEMU" "${args[@]}" \
    -name "bladerunner-$VM_ARCH" -m "$VM_MEM" -smp "$VM_SMP" \
    -display none -serial "file:$VM_CONSOLE" -monitor none \
    -pidfile "$VM_PIDFILE" -daemonize \
    -drive "file=$VM_DISK,if=virtio,format=qcow2" \
    -drive "file=$VM_DIR/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:$VM_SSH_PORT-:22" \
    -device "virtio-net-pci,netdev=mgmt,mac=$VM_MAC_MGMT" \
    -netdev "stream,id=t0,server=on,addr.type=inet,addr.host=127.0.0.1,addr.port=$VM_NET_PORT" \
    -device "$testnic" \
    || die "$VM_ARCH: QEMU failed to start"
  on_exit "vm_stop"
}

# vm_stop: terminate the VM (idempotent).
vm_stop() {
  [ -f "${VM_PIDFILE:-}" ] || return 0
  local pid; pid=$(cat "$VM_PIDFILE" 2>/dev/null) || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local _; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$VM_PIDFILE"
}

# vm_ssh CMD...: run a command in the guest. Quote it as ONE string when it
# contains shell syntax: vm_ssh 'a | b'.
# shellcheck disable=SC2029  # command is deliberately expanded on the client
vm_ssh() { ssh "${VM_SSH_OPTS[@]}" "$VM_USER@127.0.0.1" "$@"; }
# vm_scp SRC... DEST: copy host files into the guest (DEST is a guest path).
vm_scp() { local dest=${*: -1} srcs=("${@:1:$#-1}"); scp -q "${VM_SCP_OPTS[@]}" "${srcs[@]}" "$VM_USER@127.0.0.1:$dest"; }

# vm_wait_ready: wait until SSH answers, cloud-init has finished and the test
# NIC has its address. Dumps the console tail and fails on timeout.
vm_wait_ready() {
  local deadline=$((SECONDS + VM_BOOT_TIMEOUT))
  log "$VM_ARCH: waiting up to ${VM_BOOT_TIMEOUT}s for the guest to boot"
  until vm_ssh true 2>/dev/null; do
    if ! kill -0 "$(cat "$VM_PIDFILE" 2>/dev/null)" 2>/dev/null; then vm_console_tail; die "$VM_ARCH: QEMU exited"; fi
    [ $SECONDS -lt $deadline ] || { vm_console_tail; die "$VM_ARCH: SSH not up after ${VM_BOOT_TIMEOUT}s"; }
    sleep 3
  done
  vm_ssh 'sudo cloud-init status --wait >/dev/null 2>&1 || true'
  retry 30 2 vm_ssh "ip -4 addr show test0 | grep -q 'inet $VM_TEST_IP/'" \
    || { vm_console_tail; die "$VM_ARCH: test0 never got $VM_TEST_IP"; }
  log "$VM_ARCH: guest ready: $(vm_ssh 'uname -srm')"
}

# vm_console_tail: show the end of the serial console (for failures).
vm_console_tail() {
  [ -f "$VM_CONSOLE" ] || return 0
  warn "---- $VM_ARCH console (last 40 lines) ----"
  tail -n 40 "$VM_CONSOLE" >&2 || true
}
