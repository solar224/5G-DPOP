.PHONY: all build ebpf agent api-server web clean test

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
AGENT_BINARY=bin/agent
API_SERVER_BINARY=bin/api-server

# eBPF parameters
CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

# Directories
BPF_SRC_DIR := internal/ebpf/bpf
BPF_OBJ_DIR := internal/ebpf/bpf

all: deps ebpf build

deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build eBPF programs
ebpf: $(BPF_OBJ_DIR)/upf_monitor.bpf.o

$(BPF_OBJ_DIR)/upf_monitor.bpf.o: $(BPF_SRC_DIR)/upf_monitor.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# Generate Go bindings from eBPF (using bpf2go)
ebpf-gen:
	cd internal/ebpf && go generate ./...

# Build all Go binaries
build: build-agent build-api-server

build-agent:
	$(GOBUILD) -o $(AGENT_BINARY) ./cmd/agent

build-api-server:
	$(GOBUILD) -o $(API_SERVER_BINARY) ./cmd/api-server

# Build and run
run-agent: build-agent
	sudo $(AGENT_BINARY)

run-api-server: build-api-server
	$(API_SERVER_BINARY)

# Web frontend
web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

# Docker compose
compose-up:
	docker compose -f deployments/docker-compose.yaml up -d

compose-down:
	docker compose -f deployments/docker-compose.yaml down

compose-logs:
	docker compose -f deployments/docker-compose.yaml logs -f

# Testing
test:
	$(GOTEST) -v ./...

test-integration:
	$(GOTEST) -v -tags=integration ./test/integration/...

test-e2e:
	$(GOTEST) -v -tags=e2e ./test/e2e/...

# Clean
clean:
	$(GOCLEAN)
	rm -f $(AGENT_BINARY)
	rm -f $(API_SERVER_BINARY)
	rm -f $(BPF_OBJ_DIR)/*.o

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Build everything (deps, ebpf, binaries)"
	@echo "  deps             - Download Go dependencies"
	@echo "  ebpf             - Compile eBPF programs"
	@echo "  build            - Build all Go binaries"
	@echo "  build-agent      - Build agent binary"
	@echo "  build-api-server - Build API server binary"
	@echo "  run-agent        - Build and run agent (requires sudo)"
	@echo "  run-api-server   - Build and run API server"
	@echo "  web-install      - Install web dependencies"
	@echo "  web-dev          - Run web dev server"
	@echo "  web-build        - Build web for production"
	@echo "  compose-up       - Start observability stack"
	@echo "  compose-down     - Stop observability stack"
	@echo "  test             - Run unit tests"
	@echo "  clean            - Clean build artifacts"
