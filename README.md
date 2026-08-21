# PyPI DAST MVP

Ubuntu/Linux에서 PyPI 패키지를 다운로드하고, artifact 유형을 확인한 뒤, 단계별 runtime log와 JSON report를 생성하는 MVP입니다. 현재 로컬 실행 경로는 개발 검증용이며, 실제 패키지 실행은 반드시 Docker + gVisor `runsc` adapter로 격리해야 합니다. 호스트에서 임의 패키지를 직접 실행하지 않도록 production profile은 아직 차단하는 것이 원칙입니다.

## 실행

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
./dast doctor
./dast analyze requests==2.31.0 --network restricted
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

API: `POST /api/analysis`, `GET /api/analysis`, `GET /api/analysis/{id}`, `/events`, `/findings`.

## 구조

- `backend/app/package.py`: resolve/download/inspect/build/install/import/execute stage orchestration
- `backend/app/sandbox.py`: Docker `--runtime runsc`, network, resource limit command builder
- `backend/app/collectors.py`: filesystem diff와 normalized runtime event 기반
- `backend/app/analyzer.py`: rule-based finding, scoring, basic correlation
- `data/analyses/<UUID>/report.json`: 결과 저장 위치

## 현재 한계

MVP는 실제 Docker gVisor 내부 collector, DNS/pcap, `/proc`, cgroup, eBPF collector를 아직 연결하지 않았습니다. report에는 collector 상태를 `unavailable`/`disabled`로 명시하며 가짜 telemetry를 만들지 않습니다. 다음 단계는 sandbox runner를 pipeline stage의 실행 backend로 연결하고 fixture package와 API worker를 추가하는 것입니다.
