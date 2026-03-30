SHELL := /bin/sh
.DEFAULT_GOAL := build

GO ?= go

BIN_DIR ?= ./bin
BINARY ?= $(BIN_DIR)/rop-gadget
ARGS ?=

.PHONY: help fmt test build run smoke clean

help:
	@printf '%s\n' \
		'Targets:' \
		'  make fmt    - Format Go sources with gofmt' \
		'  make test   - Run the Go test suite' \
		'  make build  - Build the CLI binary at $(BINARY)' \
		'  make run    - Run the CLI with optional ARGS="..."' \
		'  make smoke  - Run a simple fixture-based gadget search' \
		'  make clean  - Remove the built CLI binary directory'

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BINARY) ./cli

run:
	$(GO) run ./cli $(ARGS)

smoke:
	$(GO) run ./cli --binary ./testdata/test-suite-binaries/elf-Linux-x86 --depth 3

clean:
	rm -rf $(BIN_DIR)
