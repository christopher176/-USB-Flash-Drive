.PHONY: help setup setup-frontend dev dev-agent dev-frontend test build clean audit

help:
	@echo "USB Shield targets:"
	@echo "  make setup          - create agent venv + install python deps"
	@echo "  make setup-frontend - npm install for the dashboard"
	@echo "  make dev-agent      - run the local scanning agent (127.0.0.1:8765)"
	@echo "  make dev-frontend   - run the web dashboard (localhost:3847)"
	@echo "  make test           - run the full agent test-suite"
	@echo "  make build          - type-check + production build of the dashboard"
	@echo "  make audit          - dependency vulnerability scan (pip-audit, npm audit)"
	@echo "  make clean          - remove build/runtime artifacts (NOT ~/.usb-shield)"

setup:
	python3 -m venv agent/.venv
	agent/.venv/bin/pip install --upgrade pip
	agent/.venv/bin/pip install -r agent/requirements-dev.txt

setup-frontend:
	cd frontend && npm install

dev-agent:
	bash scripts/dev-agent.sh

dev-frontend:
	bash scripts/dev-frontend.sh

test:
	cd agent && .venv/bin/python -m pytest tests/ -q

build:
	cd frontend && npm run build

audit:
	-agent/.venv/bin/pip install -q pip-audit && agent/.venv/bin/pip-audit -r agent/requirements.txt
	-cd frontend && npm audit --omit=dev

clean:
	rm -rf frontend/dist agent/.pytest_cache agent/.ruff_cache
	find agent -name __pycache__ -type d -prune -exec rm -rf {} +
	@echo "kept runtime data in agent/data (and ~/.usb-shield); delete manually if desired"
