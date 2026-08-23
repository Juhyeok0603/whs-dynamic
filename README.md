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

- `backend/app/package.py`: resolve/download/inspect/build/install/import/probe:*/execute stage orchestration
- `backend/app/sandbox.py`: Docker `--runtime runsc`, network, resource limit command builder
- `backend/app/collectors.py`: filesystem diff와 normalized runtime event 기반
- `backend/app/analyzer.py`: rule-based finding, scoring, basic correlation
- `data/analyses/<UUID>/report.json`: 통합 JSON 결과 저장 위치
- `data/analyses/<UUID>/logs/`: 같은 분석의 npm 쪽 모듈과 동일한 파일 단위 산출물 — `package.log`(stage별 stdout/stderr), `fs-diff.log`, `exit-code.txt`(install stage), `dns.log`(pcap에서 디코딩한 조회 도메인), `netsim.json`(network=sinkhole일 때만 실제 캡처 내용, 그 외엔 정직한 stub — 아래 참고), `network.pcap`(원본 캡처, network=full/sinkhole일 때만), `gvisor-trace.json`(behavior 전체), `resource.json`(리소스 시계열). `GET /api/analysis/{id}/logs`로 목록, `GET /api/analysis/{id}/logs/{filename}`로 개별 조회/다운로드 — 대시보드 상세 패널의 "산출물 파일" 섹션이 이걸 그대로 씀
- 시그널 추출 파이프라인(판정 없이, 이후 AI 판정 입력을 만들기 위한 원본 로그 + 정규화 산출물): 원본은 `package-metadata.json`(아티팩트 자체 METADATA/PKG-INFO의 선언 의존성), `registry-meta.json`(PyPI 게시 이력/메인테이너), `static-scan.json`(소스 문자열 엔트로피·의심 API·직전 릴리스 diff), `domain-intel.json`(dns.log 도메인별 WHOIS·엔트로피·평판 — 도메인당 최대 10개), `env-access.log`/`code-exec.log`(sandboxed 단계에 `sitecustomize.py`를 `PYTHONPATH`로 자동 로드해 `sys.addaudithook` + `os.environ` 몽키패치로 남긴 JSONL, `backend/app/instrumentation.py`). 정규화 산출물은 `backend/app/signals.py`가 위 전부와 기존 behavior/resource/fs-diff를 합쳐서 만드는 `process_signals.json`, `filesystem_signals.json`, `network_signals.json`(TLS ClientHello SNI는 `backend/app/pcap_tls.py`가 별도 라이브러리 없이 pcap을 직접 파싱), `env_signals.json`, `timing_signals.json`, `evasion_signals.json`, `code_signals.json`, `reputation_context.json`, `correlations.json`, `events.jsonl`(통합 타임라인), `summary.json`. `network_signals.json.http_body_credential_patterns`는 `network=sinkhole`이 아니면 정직하게 `not_implemented`, `VT_API_KEY` 미설정 시 `domain-intel.json`의 malicious IOC 평판도 정직하게 stub.

`disabled`와 `restricted`는 현재 모두 `--network none`으로 fail-closed 동작합니다. `full`은 Docker bridge 네트워크로 실제 인터넷에 나갑니다(관찰만, 가로채지 않음). `sinkhole`도 bridge를 쓰지만 컨테이너의 DNS를 `backend/app/sinkhole.py`가 띄우는 로컬 응답기로 강제해 모든 이름 해석이 우리 자신의 IP로만 돌아오게 하고, 443/80으로 들어오는 연결을 그 자리에서 TLS 종단(analysis마다 새로 발급하는 CA로 SNI별 leaf 인증서를 즉석 서명, `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`로 컨테이너에 신뢰시킴)해 HTTP 요청 바디에서 자격증명 패턴을 검사한 뒤 절대 실제 목적지로 전달하지 않습니다 — 격리 관점에서는 `full`보다 오히려 안전합니다. 53/80/443 바인딩은 `scripts/setup_ubuntu.sh`가 `python3`에 `cap_net_bind_service`를 부여해야 동작하며, 없으면 다른 collector들과 동일하게 `collector_status.sinkhole`에 사유만 남기고 조용히 비활성화됩니다. `verify=False`로 검증을 끄거나 자체 CA 번들을 고정하는 코드는 이 MITM으로도 못 잡습니다. allowlist proxy와 `169.254.169.254` 차단 정책을 별도로 구성하기 전에는 `full`을 신중하게만 사용하세요.

## 현재 한계

gVisor strace collector는 `runsc-trace` Docker runtime(`--debug --strace --debug-log=/var/log/runsc/`)이 등록된 경우 sandboxed stage(sdist면 build, install, import, probe:*, execute)의 exec/connect/privilege/escape/DNS(port 53)/sensitive-open syscall을 report event로 수집합니다. build/install 단계도 관찰 대상이라 `setup.py`/PEP517 빌드 훅에서 터지는 코드까지 잡히며, analyzer는 그 단계에서 항상 나오는 우리 자신의 `pip install` 호출만 `python.runtime_install` 룰에서 예외 처리합니다(다른 룰은 그대로 적용). import 이후에는 패키지 자신의 `entry_points.txt`에 등록된 콘솔 스크립트를 최대 3개까지 `--help`로 실행해(`probe:<script>` stage) bare import보다 한 단계 더 실행 경로를 관찰합니다 — 임의 내부 함수 호출까지는 하지 않는 선에서 최소한의 post-import 체크입니다. `scripts/setup_ubuntu.sh`가 runtime과 `/var/log/runsc`를 함께 등록하며, 로그 파일은 누적되므로 주기적으로 `sudo rm -f /var/log/runsc/*` 정리가 필요합니다.

추가 collector: `/proc`(runsc 프로세스 RSS)과 docker cgroup(memory/pids/cpu)은 sandboxed stage 동안 background thread로 0.5초 간격 샘플링되어 `resource_usage`에 최댓값과 함께 전체 시계열(`series`)로 기록됩니다. pcap은 tcpdump로 docker0을 캡처하며(`--network full`일 때만 의미 있음, tcpdump에 `cap_net_raw` 필요), 원본 캡처 파일은 `data/analyses/<UUID>/logs/network.pcap`에 영구 저장되고 DNS 질의 도메인명은 캡처된 패킷을 디코딩해 `behavior.dns_domains`로 별도 추출합니다(strace 기반 `behavior.dns`는 IP:port 수준의 연결 시도만 표시 — 네트워크가 막혀 있어도 잡히지만 도메인명은 모름). eBPF는 bpftrace 기반 host-boundary 관찰자로 `sudo NOPASSWD` 등록이 필요합니다 — 이 셋 다 setup 스크립트가 설정합니다. eBPF 관찰은 host 전체가 대상이라 analyzer 채점에는 넣지 않고 `behavior.host_boundary`에 교차검증용으로만 기록합니다. 각 collector는 전제조건이 빠지면 report에 사유를 명시하고 가짜 telemetry를 만들지 않습니다. 다음 단계는 fixture package와 API worker 추가입니다.
