#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "사용법: sudo ./scripts/setup_ubuntu.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release docker.io \
  python3 python3.12-venv python3-pip python3-dev \
  tcpdump libpcap-dev iproute2 nftables iptables clang llvm bpftrace openssl \
  linux-headers-$(uname -r) jq git

tool_packages=(linux-tools-common)
if apt-cache show "linux-tools-$(uname -r)" >/dev/null 2>&1; then
  tool_packages+=("linux-tools-$(uname -r)")
elif apt-cache show linux-tools-generic >/dev/null 2>&1; then
  tool_packages+=(linux-tools-generic)
fi
if ! apt-get install -y "${tool_packages[@]}"; then
  echo "WARN: kernel eBPF tools could not be installed; collector will be unavailable"
fi
systemctl enable --now docker

install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /etc/apt/keyrings/gvisor.gpg
printf '%s\n' 'deb [arch=amd64 signed-by=/etc/apt/keyrings/gvisor.gpg] https://storage.googleapis.com/gvisor/releases release main' > /etc/apt/sources.list.d/gvisor.list
apt-get update
apt-get install -y runsc

install -d -m 0755 /etc/docker
if [[ -f /etc/docker/daemon.json ]]; then
  cp /etc/docker/daemon.json "/etc/docker/daemon.json.backup.$(date +%s)"
fi
install -d -m 0755 /var/log/runsc
cat > /etc/docker/daemon.json <<'JSON'
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    },
    "runsc-trace": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": ["--debug", "--strace", "--debug-log=/var/log/runsc/"]
    }
  }
}
JSON
systemctl restart docker

# pcap: let the non-root pipeline start tcpdump
setcap cap_net_raw,cap_net_admin+ep "$(command -v tcpdump)"

# sinkhole (network=sinkhole, the default): let the non-root pipeline bind DNS/HTTP/HTTPS on 53/80/443.
# python3 in a venv is normally a symlink to this same interpreter, so the venv inherits the capability too.
setcap cap_net_bind_service+ep "$(readlink -f "$(command -v python3)")"

# sinkhole's host-level NAT (catches hardcoded-IP exfil that skips DNS entirely): iptables needs
# cap_net_admin to manage netfilter rules without full root. docker network create/rm needs no extra
# capability beyond the docker group membership this script already assumes.
setcap cap_net_admin,cap_net_raw+ep "$(command -v iptables)"

# eBPF: let the non-root pipeline start/stop bpftrace without a password prompt
analysis_user="${SUDO_USER:-$USER}"
printf '%s\n' "${analysis_user} ALL=(root) NOPASSWD: $(command -v bpftrace), /usr/bin/pkill -x bpftrace" > /etc/sudoers.d/pypi-dast
chmod 0440 /etc/sudoers.d/pypi-dast

chmod +x dast scripts/*.sh

runsc --version
docker info --format 'Docker {{.ServerVersion}}; runtimes={{json .Runtimes}}'
python3 --version
python3 -m pip --version
echo "Ubuntu environment setup complete. Run ./scripts/check_environment.sh"
