PYTHON ?= python3

install:
	$(PYTHON) -m pip install -r requirements.txt

doctor:
	./dast doctor

server:
	$(PYTHON) -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000

test:
	$(PYTHON) -m pytest -q
