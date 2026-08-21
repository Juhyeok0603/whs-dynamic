#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "사용법: sudo ./scripts/setup_ubuntu.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release docker.io \
  python3 python3-venv python3-pip python3-dev \
  tcpdump libpcap-dev iproute2 nftables bpftool clang llvm \
  linux-headers-$(uname -r) jq git
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
cat > /etc/docker/daemon.json <<'JSON'
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  }
}
JSON
systemctl restart docker

runsc --version
docker info --format 'Docker {{.ServerVersion}}; runtimes={{json .Runtimes}}'
python3 --version
pip3 --version
echo "Ubuntu environment setup complete. Run ./scripts/check_environment.sh"
