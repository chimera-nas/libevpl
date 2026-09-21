#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
# Run the already-built Coverage binaries in the same container image, inside
# a KVM guest whose kernel supplies Soft-RoCE. No host RDMA modules are needed.
set -euo pipefail
image=${1:?usage: run_rdma_vm.sh CONTAINER_IMAGE}
root=$PWD
out=$root/coverage-output
vm=$(mktemp -d)
qemu_pid=
cleanup() {
    if [[ -n "$qemu_pid" ]]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$vm"
}
trap cleanup EXIT
mkdir -p "$out"
test -c /dev/kvm || { echo 'KVM is required for the RDMA coverage lane' >&2; exit 1; }
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils
sudo chmod a+rw /dev/kvm
ssh-keygen -q -t ed25519 -N '' -f "$vm/key"
key=$(cat "$vm/key.pub")
cat > "$vm/user-data" <<CLOUD
#cloud-config
users:
  - name: evpl
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $key
package_update: true
packages:
  - linux-image-generic
  - docker.io
  - rdma-core
  - ibverbs-providers
  - ibverbs-utils
  - rdmacm-utils
runcmd:
  - [systemctl, enable, --now, docker]
CLOUD
printf 'instance-id: evpl-rdma\nlocal-hostname: evpl-rdma\n' > "$vm/meta-data"
cloud-localds "$vm/seed.img" "$vm/user-data" "$vm/meta-data"
base=https://cloud-images.ubuntu.com/noble/current
curl --fail --location --retry 3 "$base/SHA256SUMS" -o "$vm/SHA256SUMS"
curl --fail --location --retry 3 "$base/noble-server-cloudimg-amd64.img" -o "$vm/noble-server-cloudimg-amd64.img"
(cd "$vm"; awk '$2 == "*noble-server-cloudimg-amd64.img" || $2 == "noble-server-cloudimg-amd64.img"' SHA256SUMS > image.sha256; test -s image.sha256; sha256sum -c image.sha256)
qemu-img resize "$vm/noble-server-cloudimg-amd64.img" 24G
# QEMU accesses shared files as the runner user, including profiles written by
# root in the build container. Preserve that ownership across guest writes.
sudo chown -R "$(id -u):$(id -g)" coverage-build coverage-output
qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 6144 -nographic \
    -drive "file=$vm/noble-server-cloudimg-amd64.img,if=virtio,format=qcow2" \
    -drive "file=$vm/seed.img,if=virtio,format=raw" \
    -netdev user,id=net,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=net \
    -virtfs "local,path=$root,mount_tag=workspace,security_model=none,id=workspace" \
    > "$out/rdma-vm-console.log" 2>&1 &
qemu_pid=$!
ssh_vm() {
    ssh -i "$vm/key" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o ServerAliveInterval=15 evpl@127.0.0.1 "$@"
}
wait_ssh() {
    for ((i=0; i<120; i++)); do
        kill -0 "$qemu_pid" || return 1
        if ssh_vm true 2>/dev/null; then return 0; fi
        sleep 5
    done
    echo 'Timed out waiting for guest SSH' >&2
    return 1
}
wait_ssh
ssh_vm 'sudo cloud-init status --wait --long' || {
    ssh_vm 'sudo cat /var/log/cloud-init-output.log' || true
    exit 1
}
# The cloud image starts with the virtual kernel, which omits RXE. Boot the
# generic kernel installed above before creating the software RDMA device.
boot_id=$(ssh_vm cat /proc/sys/kernel/random/boot_id)
ssh_vm 'sudo reboot' || true
for ((i=0; i<120; i++)); do
    new_id=$(ssh_vm cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    if [[ -n "$new_id" && "$new_id" != "$boot_id" ]]; then break; fi
    sleep 5
 done
[[ -n "$new_id" && "$new_id" != "$boot_id" ]]
ssh_vm 'sudo bash -s' <<'GUEST'
set -euxo pipefail
uname -a
modprobe rdma_rxe
iface=$(ip -o -4 route show default | awk '{print $5; exit}')
# The UD regression sends datagrams up to 4000 bytes (RDMA MTU 4096).
ip link set dev "$iface" mtu 9000
ip addr add 192.0.2.1/24 dev "$iface"
rdma link add rxe0 type rxe netdev "$iface"
rdma link show
ibv_devinfo -d rxe0
ulimit -l unlimited
rping -s -a 192.0.2.1 -p 7471 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
sleep 1
timeout 30 rping -c -a 192.0.2.1 -p 7471 -C 8 -v
mkdir -p /workspace
mount -t 9p -o trans=virtio,version=9p2000.L workspace /workspace
GUEST
# Reuse the exact userspace and executable build, not a second compilation.
docker save "$image" | ssh_vm sudo docker load
ssh_vm sudo docker run --rm --privileged --network=host --ulimit memlock=-1:-1 \
    -e FI_PROVIDER=tcp -v /workspace:/workspace -v /workspace/coverage-build:/build -w /workspace \
    "$image" bash scripts/run_rdma_tests.sh
