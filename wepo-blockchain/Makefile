# WEPO Blockchain Makefile

.PHONY: all install clean test run-node run-miner run-wallet-daemon help

# Default Python executable
PYTHON ?= python3
PIP ?= pip3

# Installation directories
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

# Version
VERSION = 1.0.0

help:
	@echo "WEPO Blockchain Build System"
	@echo "============================"
	@echo ""
	@echo "Available targets:"
	@echo "  install        - Install WEPO blockchain software"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  run-node       - Run WEPO full node"
	@echo "  run-miner      - Run WEPO miner"
	@echo "  run-wallet     - Run wallet daemon"
	@echo "  package        - Create distribution packages"
	@echo "  help           - Show this help"

install: install-deps install-bins

install-deps:
	@echo "Installing Python dependencies..."
	$(PIP) install -r requirements.txt

install-bins:
	@echo "Installing WEPO binaries..."
	install -d $(BINDIR)
	install -m 755 core/wepo_node.py $(BINDIR)/wepo-node
	install -m 755 miner/wepo_miner.py $(BINDIR)/wepo-miner
	install -m 755 wallet-daemon/wepo_walletd.py $(BINDIR)/wepo-walletd
	@echo "WEPO blockchain installed to $(BINDIR)"

clean:
	@echo "Cleaning build artifacts..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/
	rm -rf /tmp/wepo/

test:
	@echo "Running WEPO blockchain tests..."
	$(PYTHON) -m pytest tests/ -v

run-node:
	@echo "Starting WEPO full node..."
	$(PYTHON) core/wepo_node.py --data-dir ./data/node1

run-miner:
	@echo "Starting WEPO miner..."
	$(PYTHON) miner/wepo_miner.py --node http://localhost:8001 --address wepo1miner0000000000000000000000000

run-wallet:
	@echo "Starting WEPO wallet daemon..."
	$(PYTHON) wallet-daemon/wepo_walletd.py --node-host localhost --node-port 8001

test-blockchain:
	@echo "Testing WEPO blockchain core..."
	$(PYTHON) core/blockchain.py

test-miner:
	@echo "Testing WEPO miner..."
	$(PYTHON) miner/wepo_miner.py --test --address wepo1test000000000000000000000000

test-network:
	@echo "Testing WEPO P2P network..."
	$(PYTHON) core/p2p_network.py

package:
	@echo "Creating WEPO distribution packages..."
	mkdir -p dist/
	tar -czf dist/wepo-blockchain-$(VERSION).tar.gz \
		--exclude='.git' \
		--exclude='__pycache__' \
		--exclude='*.pyc' \
		--exclude='data/' \
		--exclude='dist/' \
		.
	@echo "Package created: dist/wepo-blockchain-$(VERSION).tar.gz"

# Docker targets
docker-build:
	@echo "Building WEPO Docker images..."
	docker build -t wepo/node:$(VERSION) -f docker/Dockerfile.node .
	docker build -t wepo/miner:$(VERSION) -f docker/Dockerfile.miner .
	docker build -t wepo/wallet:$(VERSION) -f docker/Dockerfile.wallet .

docker-run-node:
	@echo "Running WEPO node in Docker..."
	docker run -p 22567:22567 -p 8001:8001 -v wepo-data:/data wepo/node:$(VERSION)

docker-run-miner:
	@echo "Running WEPO miner in Docker..."
	docker run --network host wepo/miner:$(VERSION)

# Development targets
dev-setup:
	@echo "Setting up development environment..."
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-asyncio black isort flake8
	mkdir -p data/node1 data/node2 data/miner logs

dev-test-network:
	@echo "Testing P2P network with multiple nodes..."
	$(PYTHON) core/wepo_node.py --data-dir ./data/node1 --p2p-port 22567 --api-port 8001 &
	sleep 5
	$(PYTHON) core/wepo_node.py --data-dir ./data/node2 --p2p-port 22568 --api-port 8002 --no-mining &
	sleep 10
	$(PYTHON) miner/wepo_miner.py --node http://localhost:8001 --address wepo1miner0000000000000000000000000 --threads 1 &
	@echo "Network started. Check logs or press Ctrl+C to stop."

format:
	@echo "Formatting Python code..."
	black core/ miner/ wallet-daemon/ tests/
	isort core/ miner/ wallet-daemon/ tests/

lint:
	@echo "Linting Python code..."
	flake8 core/ miner/ wallet-daemon/ tests/ --max-line-length=100

# System service installation (Linux)
install-service:
	@echo "Installing WEPO systemd services..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Must run as root to install services"; \
		exit 1; \
	fi
	cp scripts/wepo-node.service /etc/systemd/system/
	cp scripts/wepo-miner.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Services installed. Enable with: systemctl enable wepo-node wepo-miner"

uninstall:
	@echo "Uninstalling WEPO blockchain..."
	rm -f $(BINDIR)/wepo-node $(BINDIR)/wepo-miner $(BINDIR)/wepo-walletd
	rm -f /etc/systemd/system/wepo-*.service
	systemctl daemon-reload 2>/dev/null || true
	@echo "WEPO blockchain uninstalled"

# Cross-compilation targets
build-linux:
	@echo "Building for Linux..."
	# Add PyInstaller or similar for binary creation

build-windows:
	@echo "Building for Windows..."
	# Add cross-compilation for Windows

build-macos:
	@echo "Building for macOS..."
	# Add cross-compilation for macOS

all: install

.DEFAULT_GOAL := help