# Host eBPF collector

Host eBPF is an optional boundary collector. It does not replace gVisor application telemetry.

It may observe:

- runsc/container lifecycle
- host-visible process activity
- host-visible networking
- cgroup correlation

The collector must report `disabled` or `unavailable` when kernel support, `bpftool`, or privileges are missing. It must never synthesize events.

```bash
bpftool feature probe
uname -r
cat /sys/fs/cgroup/cgroup.controllers
```
