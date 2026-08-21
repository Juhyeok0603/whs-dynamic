# PyPI DAST MVP

Ubuntu/Linux에서 PyPI 패키지를 다운로드하고, artifact 유형을 확인한 뒤, 단계별 runtime log와 JSON report를 생성하는 MVP입니다. 현재 로컬 실행 경로는 개발 검증용이며, 실제 패키지 실행은 반드시 Docker + gVisor `runsc` adapter로 격리해야 합니다. 호스트에서 임의 패키지를 직접 실행하지 않도록 production profile은 아직 차단하는 것이 원칙입니다.

## Ubuntu 24.04 VM 준비

실제 분석은 Ubuntu 24.04 VM에서 실행합니다. Windows는 개발 환경으로만 사용하고, 저장소를 VM 안으로 가져온 뒤 다음 명령을 실행하세요.

```bash
sudo bash scripts/setup_ubuntu.sh
bash scripts/check_environment.sh
```

설치 대상은 Docker, gVisor `runsc`, Python/pip, tcpdump/libpcap, iproute2, nftables, bpftool, clang/LLVM, kernel headers입니다. 설치 스크립트는 기존 Docker 설정을 timestamp 백업한 뒤 `runsc`를 Docker runtime으로 등록합니다.

분석용 dummy credential은 실제 사용자 파일과 분리된 경로에 생성합니다.

```bash
bash scripts/create_fake_credentials.sh
```

## 실행

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 dast doctor
python3 dast analyze requests==2.31.0 --network disabled
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

컨테이너는 현재 사용자의 UID/GID로 실행되어 호스트 임시 디렉터리를 root 소유로 만들지 않습니다. 이전 실패 실행에서 남은 임시 파일이 있다면 한 번만 정리하세요.

```bash
sudo rm -rf /tmp/pypi-dast-*
```

API: `POST /api/analysis`, `GET /api/analysis`, `GET /api/analysis/{id}`, `/events`, `/findings`. 대시보드는 서버가 `frontend/index.html`을 `/`에서 직접 서빙하므로 `uvicorn` 실행 후 `http://localhost:8000`을 그대로 열면 됩니다.

## 구조

- `backend/app/package.py`: resolve/download/inspect/build/install/import/execute stage orchestration
- `backend/app/sandbox.py`: Docker `--runtime runsc`, network, resource limit command builder
- `backend/app/collectors.py`: filesystem diff와 normalized runtime event 기반
- `backend/app/analyzer.py`: rule-based finding, scoring, basic correlation
- `data/analyses/<UUID>/report.json`: 결과 저장 위치

`disabled`와 `restricted`는 현재 모두 `--network none`으로 fail-closed 동작합니다. `full`만 Docker bridge 네트워크를 사용합니다. allowlist proxy와 `169.254.169.254` 차단 정책을 별도로 구성하기 전에는 외부 네트워크를 활성화하지 마세요.

## 현재 한계

gVisor strace collector는 `runsc-trace` Docker runtime(`--debug --strace --debug-log=/var/log/runsc/`)이 등록된 경우 import/execute stage의 exec/connect/privilege/escape/DNS(port 53)/sensitive-open syscall을 report event로 수집합니다. `scripts/setup_ubuntu.sh`가 runtime과 `/var/log/runsc`를 함께 등록하며, 로그 파일은 누적되므로 주기적으로 `sudo rm -f /var/log/runsc/*` 정리가 필요합니다.

추가 collector: `/proc`(runsc 프로세스 RSS)과 docker cgroup(memory/pids/cpu)은 sandboxed stage 동안 background thread로 샘플링되어 `resource_usage`에 기록됩니다. pcap은 tcpdump로 docker0을 캡처하며(`--network full`일 때만 의미 있음, tcpdump에 `cap_net_raw` 필요), eBPF는 bpftrace 기반 host-boundary 관찰자로 `sudo NOPASSWD` 등록이 필요합니다 — 둘 다 setup 스크립트가 설정합니다. eBPF 관찰은 host 전체가 대상이라 analyzer 채점에는 넣지 않고 `behavior.host_boundary`에 교차검증용으로만 기록합니다. 각 collector는 전제조건이 빠지면 report에 사유를 명시하고 가짜 telemetry를 만들지 않습니다. 다음 단계는 fixture package와 API worker 추가입니다.
