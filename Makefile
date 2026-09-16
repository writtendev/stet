PKG := github.com/writtendev/stet

GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -X $(PKG)/internal/version.Version=$(VERSION)

# FIDO2 selects whether the libfido2 cgo backend (internal/fido) is built.
# auto (the default) turns it on when pkg-config finds libfido2, off
# otherwise. Force it with FIDO2=1 or FIDO2=0; FIDO2=1 without libfido2
# installed fails loudly at the cgo step rather than silently falling back
# to the stub.
FIDO2 ?= auto
ifeq ($(FIDO2),auto)
FIDO2 := $(shell pkg-config --exists libfido2 && echo 1 || echo 0)
endif
TAGS := $(if $(filter 1,$(FIDO2)),libfido2,)

.PHONY: all build test lint check install clean

all: check build

build:
ifeq ($(TAGS),)
	@echo "note: building without libfido2 (hardware keys unavailable)"
endif
	mkdir -p bin
	go build -tags "$(TAGS)" -ldflags "$(LDFLAGS)" -o bin/stet ./cmd/stet

test:
	go test -tags "$(TAGS)" ./...

lint:
	golangci-lint run --build-tags "$(TAGS)"

check: build test lint

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/stet
	@printf 'installed %s to %s\n' '$(VERSION)' '$(GOBIN)/stet'

clean:
	rm -rf bin
