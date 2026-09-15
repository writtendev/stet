PKG := github.com/writtendev/stet

GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -X $(PKG)/internal/version.Version=$(VERSION)

.PHONY: all build test lint check install clean

all: check build

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/stet ./cmd/stet

test:
	go test ./...

lint:
	golangci-lint run

check: build test lint

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/stet
	@printf 'installed %s to %s\n' '$(VERSION)' '$(GOBIN)/stet'

clean:
	rm -rf bin
