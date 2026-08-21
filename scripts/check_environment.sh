#!/usr/bin/env bash
set -u
check() { if command -v "$1" >/dev/null 2>&1; then echo "[OK] $1"; else echo "[WARN] $1 unavailable"; fi; }
check docker
check runsc
check python3
check pip3
check tcpdump
check bpftool
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then echo "[OK] cgroup v2"; else echo "[WARN] cgroup v2 unavailable"; fi
if docker info >/dev/null 2>&1; then echo "[OK] Docker daemon"; else echo "[WARN] Docker daemon unavailable"; fi
