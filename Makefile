.PHONY: install test doctor lab-start lab-stop lab-verify clean lint

VENV = .venv
BIN = $(VENV)/bin

install:
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt
	$(BIN)/pip install --no-build-isolation -e .

test:
	$(BIN)/pytest -v tests/

doctor:
	$(BIN)/krypt doctor

lab-start:
	$(BIN)/krypt lab start

lab-stop:
	$(BIN)/krypt lab stop

lab-verify:
	$(BIN)/krypt lab verify

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
