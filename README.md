# PyPI DAST MVP

Ubuntu/Linux에서 PyPI 패키지를 다운로드하고, artifact 유형을 확인한 뒤, 단계별 runtime log와 JSON report를 생성하는 MVP입니다. 현재 로컬 실행 경로는 개발 검증용이며, 실제 패키지 실행은 반드시 Docker + gVisor `runsc` adapter로 격리해야 합니다. 호스트에서 임의 패키지를 직접 실행하지 않도록 production profile은 아직 차단하는 것이 원칙입니다.

## Ubuntu 24.04 VM 준비

실제 분석은 Ubuntu 24.04 VM에서 실행합니다. Windows는 개발 환경으로만 사용하고, 저장소를 VM 안으로 가져온 뒤 다음 명령을 실행하세요.

```bash
sudo bash scripts/setup_ubuntu.sh
bash scripts/check_environment.sh
```

설치 대상은 Docker, gVisor `runsc`, Python/pip, tcpdump/libpcap, iproute2, nftables, iptables, bpftool, clang/LLVM, kernel headers입니다. 설치 스크립트는 기존 Docker 설정을 timestamp 백업한 뒤 `runsc`를 Docker runtime으로 등록하고, `python3`/`iptables`에 각각 `cap_net_bind_service`/`cap_net_admin`을 부여해 sinkhole(아래 참고)이 비root로 동작하게 합니다.

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
python3 dast analyze requests==2.31.0   # 기본값이 --network sinkhole — 아래 참고
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

컨테이너는 현재 사용자의 UID/GID로 실행되어 호스트 임시 디렉터리를 root 소유로 만들지 않습니다. 이전 실패 실행에서 남은 임시 파일이 있다면 한 번만 정리하세요.

```bash
sudo rm -rf /tmp/pypi-dast-*
```

API: `POST /api/analysis`(PyPI 이름으로), `POST /api/analysis/upload`(로컬 파일로), `GET /api/analysis`, `GET /api/analysis/{id}`, `/events`, `/findings`. 대시보드는 서버가 `frontend/index.html`을 `/`에서 직접 서빙하므로 `uvicorn` 실행 후 `http://localhost:8000`을 그대로 열면 됩니다.

## 로컬 파일 업로드 분석

실제 악성 샘플은 애초에 PyPI에 없어서 이름으로 못 받아옵니다 — `POST /api/analysis/upload`(multipart, `file` 필드 + 선택적 `network`/`timeout` 폼 필드)에 `.whl`/`.tar.gz`/`.tgz`/`.zip` 아티팩트를 그대로 올리면 `pip download` 단계만 건너뛰고 나머지(inspect→build→install→import→probe→execute, 시그널 추출, sinkhole)는 PyPI 경로와 완전히 동일한 파이프라인을 탑니다(`package.analyze_package`의 `local_artifact` 파라미터). 이름/버전은 아티팩트 자체의 METADATA/PKG-INFO에서 읽고, 그것도 없으면 파일명에서 유추합니다(`package.guess_package_name`). 업로드 파일은 `SAMPLES_DIR`(기본 `samples/`, git에 안 올라감 — `.gitignore` 참고)에 분석 ID를 붙여 저장되고 분석 후에도 자동 삭제되지 않습니다(npm 사촌 프로젝트의 `samples/`와 동일한 취지 — 실제 악성코드가 로컬 디스크에 실물로 남으니, 이 프로젝트 전체와 마찬가지로 격리된 환경에서만 다루고 압축해서 옮기거나 클라우드 동기화 폴더에 두지 마세요). 대시보드에서는 "새 분석 시작" 아래 별도 파일 업로드 폼으로 접근할 수 있습니다.

PyPI 이름 경로의 "download" 스테이지는 `--no-deps` 없이 돌아서 선언된 런타임 의존성까지 같이 받아오는데,
업로드는 그 호출 자체가 없어 의존성이 workspace에 안 남는 문제가 있었다 — `package.prefetch_declared_dependencies`가
아티팩트의 `Requires-Dist` 원본 문자열(버전 제약 그대로, 정규화된 이름만 쓰면 최신 버전을 받아서 제약이
안 맞을 수 있음)로 호스트에서 최대 20개까지 미리 받아둬서 `install --no-index --find-links /workspace`가
오프라인으로도 웬만하면 만족되게 한다.

## 멀티 Python 버전 샌드박스

실제 악성 샘플 중엔 (오래된 cookiecutter 템플릿에서 그대로 찍어낸 듯) `Requires-Python: >=3.8.0,<3.9`처럼
좁은 범위만 지원하는 경우가 있습니다 — 샌드박스가 `python:3.12-slim` 하나만 썼다면 이런 패키지는
build/install이 "requires a different Python"으로 항상 실패합니다. `read_package_metadata`가 아티팩트의
`Requires-Python`을 읽고, `sandbox.select_python_image()`가 `packaging.specifiers.SpecifierSet`으로 그
제약을 만족하는 **가장 최신** 지원 버전(`3.8`~`3.13`, 전부 gVisor+계측 검증된 공식 `python:X.Y-slim` 태그)을
골라 그 이미지로 build/install/import/probe/execute를 돌립니다. 제약이 없거나 파싱 실패, 또는 지원 범위
밖(예: 3.6 이하 요구)이면 검증 안 된 이미지를 추측하지 않고 기존 기본값(`python:3.12-slim`)으로 그대로
degrade — 실제 사용된 이미지는 `report.sandbox.python_image`에서 확인 가능합니다. 처음 쓰는 버전은
`docker pull`이 필요해 호스트 자체 인터넷이 있어야 합니다(샌드박스 네트워크 모드와 무관 — 기존 `pip
download`/registry 조회와 같은 호스트 사이드 동작).

sdist를 오프라인으로 빌드하기 위해 `package.ensure_build_backends_cached()`가 `setuptools`/`wheel`/
`poetry-core`/`flit_core`/`hatchling`/`pdm-backend`/`setuptools-scm`을 호스트에서 미리 받아 `build`
스테이지에 `--no-index --find-links`로 넘겨주는데, 이 캐시는 **Python 버전별로 따로** 관리됩니다
(`data/analyses/_build_backends/<버전>/`) — 빌드 백엔드의 최신판이 오래된 Python 지원을 끊는 경우가 실제로
있어서(예: `poetry-core` 2.4.1은 Python 3.10 이상만 지원, `Requires-Python`이 3.8인 패키지엔 못 씀),
`pip download --python-version <버전> --only-binary :all:`로 호스트의 Python과 무관하게 타깃 버전에 실제로
맞는 wheel을 받아옵니다.

## 구조

- `backend/app/package.py`: resolve/download/inspect/build/install/import/probe:*/execute stage orchestration
- `backend/app/sandbox.py`: Docker `--runtime runsc`, network, resource limit command builder, `select_python_image`
- `backend/app/collectors.py`: filesystem diff와 normalized runtime event 기반
- `backend/app/analyzer.py`: rule-based finding, scoring, basic correlation
- `data/analyses/<UUID>/report.json`: 통합 JSON 결과 저장 위치
- `data/analyses/<UUID>/logs/`: 같은 분석의 npm 쪽 모듈과 동일한 파일 단위 산출물 — `package.log`(stage별 stdout/stderr), `fs-diff.log`, `exit-code.txt`(install stage), `dns.log`(pcap에서 디코딩한 조회 도메인), `netsim.json`(sinkhole이 실제로 캡처한 아웃바운드 요청 — 기본 네트워크 모드가 sinkhole이라 사실상 항상 채워짐, 실패 시에만 정직한 stub), `network.pcap`(원본 캡처), `gvisor-trace.json`(behavior 전체), `resource.json`(리소스 시계열). `GET /api/analysis/{id}/logs`로 목록, `GET /api/analysis/{id}/logs/{filename}`로 개별 조회/다운로드 — 대시보드 상세 패널의 "산출물 파일" 섹션이 이걸 그대로 씀
- 시그널 추출 파이프라인(판정 없이, 이후 AI 판정 입력을 만들기 위한 원본 로그 + 정규화 산출물): 원본은 `package-metadata.json`(아티팩트 자체 METADATA/PKG-INFO의 선언 의존성), `registry-meta.json`(PyPI 게시 이력/메인테이너), `static-scan.json`(소스 문자열 엔트로피·의심 API·직전 릴리스 diff), `domain-intel.json`(dns.log 도메인별 WHOIS·엔트로피·평판 — 도메인당 최대 10개), `env-access.log`/`code-exec.log`(sandboxed 단계에 `sitecustomize.py`를 `PYTHONPATH`로 자동 로드해 `sys.addaudithook` + `os.environ` 몽키패치로 남긴 JSONL, `backend/app/instrumentation.py`). 정규화 산출물은 `backend/app/signals.py`가 위 전부와 기존 behavior/resource/fs-diff를 합쳐서 만드는 `process_signals.json`(프로세스 트리에 depth 포함), `filesystem_signals.json`, `network_signals.json`(TLS ClientHello SNI는 `backend/app/pcap_tls.py`가 별도 라이브러리 없이 pcap을 직접 파싱; `http_body_credential_patterns`는 sinkhole 캡처를 신호 추출 시점에 스캔해서 채움 — netsim.json 자체엔 패턴 매칭 안 함, 원본/산출물 분리 원칙 유지; `ip_hardcode_bypass_attempts`는 DNS 조회 없이 접속한 IP를 별도로 표시), `env_signals.json`, `timing_signals.json`, `evasion_signals.json`, `code_signals.json`, `reputation_context.json`, `correlations.json`, `events.jsonl`(통합 타임라인), `summary.json`. `VT_API_KEY` 미설정 시 `domain-intel.json`의 malicious IOC 평판은 정직하게 stub.

## 네트워크 격리 (sinkhole, 기본값)

대시보드/CLI 기본 네트워크 모드는 `sinkhole`입니다 — 이 프로젝트는 애초에 `pip download`를 호스트에서 먼저 받아두고 컨테이너는 `--no-index`로 오프라인 설치만 하므로(위 stage 목록 참고), 샌드박스 컨테이너는 실제 네트워크가 전혀 필요 없습니다. 그래서 `sinkhole`은 예외(allowlist) 없이 **아웃바운드 전부**를 가로채도 되고, 결과적으로 `disabled`/`restricted`보다 관찰 데이터가 많고 `full`(실제 인터넷 노출)보다 안전한 상위 호환이 됩니다 — 그래서 대시보드에는 더 이상 네트워크 모드를 고르는 UI가 없습니다. `full`/`disabled` 등 다른 모드가 필요하면 API(`POST /api/analysis`의 `network` 필드)나 `dast analyze --network <mode>`로 직접 지정하세요.

`backend/app/sinkhole.py`가 분석마다:
1. 전용 Docker 네트워크(`dast-sh-<analysis id 앞 8자>`, subnet은 Docker IPAM이 자동 할당 — 동시 분석마다 안 겹치는 대역을 받아서 `main.py`의 `ThreadPoolExecutor(max_workers=2)` 동시 실행과 충돌 안 함)를 만들고 그 게이트웨이 IP에 바인딩합니다.
2. 컨테이너의 DNS를 그 IP로 강제(`--dns`)해 모든 이름 해석이 우리 자신에게 돌아오게 하고, 443/80 연결을 그 자리에서 TLS 종단(분석마다 새로 발급하는 CA로 SNI별 leaf 인증서를 즉석 서명, `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`로 컨테이너에 신뢰시킴)해 HTTP 요청 바디를 그대로 기록합니다. SNI는 `-subj`/extfile에 넣기 전에 `[A-Za-z0-9.-]` 문자셋으로 검증하고, 벗어나면 인증서 발급용으로만 안전한 placeholder로 치환합니다(로그에는 원본 그대로 남음) — 공격자가 완전히 통제하는 값이라 인젝션 방지 목적.
3. **host-level iptables DNAT**로 그 도커 네트워크 subnet에서 나가는 모든 패킷(DNS 우회하고 IP를 하드코딩하는 경우까지 포함)을 게이트웨이로 재작성합니다 — DNS 리다이렉트만으로는 못 잡는 경로를 닫아줍니다. 절대 실제 목적지로 전달하지 않습니다.

CA/Docker 네트워크 생성/포트 바인딩/iptables 규칙 중 하나라도 실패하면(openssl 없음, `cap_net_bind_service`/`cap_net_admin` 미설정 등) `collector_status.sinkhole`에 사유만 남기고, **그 경우 실제 네트워크는 `restricted`(`--network none`)로 강제 전환**됩니다 — sinkhole이 실패했는데 조용히 `bridge`로 fail-open해서 실제 인터넷에 노출시키는 일은 없습니다. `verify=False`로 TLS 검증을 끄거나 자체 CA 번들을 고정하는 코드, DNAT가 포트는 바꾸지 않으므로 80/443이 아닌 포트로 나가는 트래픽은 이 MITM으로도 못 잡습니다(연결 자체는 게이트웨이로 리다이렉트돼 실제 인터넷엔 안 나가지만, 그 포트에서 듣고 있지 않아 요청 내용은 안 남음 — npm 쪽 sinkhole과 동일한 제약).

## 현재 한계

gVisor strace collector는 `runsc-trace` Docker runtime(`--debug --strace --debug-log=/var/log/runsc/`)이 등록된 경우 sandboxed stage(sdist면 build, install, import, probe:*, execute)의 exec/connect/privilege/escape/DNS(port 53)/sensitive-open syscall을 report event로 수집합니다. build/install 단계도 관찰 대상이라 `setup.py`/PEP517 빌드 훅에서 터지는 코드까지 잡히며, analyzer는 그 단계에서 항상 나오는 우리 자신의 `pip install` 호출만 `python.runtime_install` 룰에서 예외 처리합니다(다른 룰은 그대로 적용). import 이후에는 패키지 자신의 `entry_points.txt`에 등록된 콘솔 스크립트를 최대 3개까지 `--help`로 실행해(`probe:<script>` stage) bare import보다 한 단계 더 실행 경로를 관찰합니다 — 임의 내부 함수 호출까지는 하지 않는 선에서 최소한의 post-import 체크입니다. `scripts/setup_ubuntu.sh`가 runtime과 `/var/log/runsc`를 함께 등록하며, 로그 파일은 누적되므로 주기적으로 `sudo rm -f /var/log/runsc/*` 정리가 필요합니다.

추가 collector: `/proc`(runsc 프로세스 RSS)과 docker cgroup(memory/pids/cpu)은 sandboxed stage 동안 background thread로 0.5초 간격 샘플링되어 `resource_usage`에 최댓값과 함께 전체 시계열(`series`)로 기록됩니다. pcap은 tcpdump로 (기본값인 sinkhole을 포함해) `disabled`/`restricted`가 아닌 네트워크 모드에서 브릿지 인터페이스를 캡처하며(tcpdump에 `cap_net_raw` 필요), 원본 캡처 파일은 `data/analyses/<UUID>/logs/network.pcap`에 영구 저장되고 DNS 질의 도메인명은 캡처된 패킷을 디코딩해 `behavior.dns_domains`로 별도 추출합니다(strace 기반 `behavior.dns`는 IP:port 수준의 연결 시도만 표시 — 네트워크가 막혀 있어도 잡히지만 도메인명은 모름). eBPF는 bpftrace 기반 host-boundary 관찰자로 `sudo NOPASSWD` 등록이 필요합니다 — 이 셋 다 setup 스크립트가 설정합니다. eBPF 관찰은 host 전체가 대상이라 analyzer 채점에는 넣지 않고 `behavior.host_boundary`에 교차검증용으로만 기록합니다. 각 collector는 전제조건이 빠지면 report에 사유를 명시하고 가짜 telemetry를 만들지 않습니다. 다음 단계는 fixture package와 API worker 추가입니다.
