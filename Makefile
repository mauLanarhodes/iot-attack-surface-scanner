.PHONY: setup run run-example clean help

help:
	@echo "IoT Attack Surface Scanner — Makefile targets"
	@echo ""
	@echo "  make setup        Create venv and install dependencies"
	@echo "  make run          Launch the scanner (prompts for subnet)"
	@echo "  make run-example  Run scanner on example subnet (192.168.1.0/24)"
	@echo "  make clean        Remove venv and cache files"
	@echo ""

setup:
	@echo "Creating virtual environment..."
	python3 -m venv venv
	@echo "Activating venv and installing dependencies..."
	@. venv/bin/activate && pip install -r requirements.txt
	@echo "✓ Setup complete! Run 'source venv/bin/activate' to activate the venv."

run:
	@read -p "Enter target subnet (e.g., 192.168.1.0/24): " subnet; \
	. venv/bin/activate && python3 main.py $$subnet

run-example:
	@. venv/bin/activate && python3 main.py 192.168.1.0/24

clean:
	rm -rf venv __pycache__ .pytest_cache iotscanner/__pycache__ iotscanner/*/__pycache__
	@echo "✓ Cleaned up"
