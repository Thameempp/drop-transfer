# drop — common tasks. Requires Go (see go.mod); Git only for the Git commands and some tests.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
BINDIR ?=
LDFLAGS := -X github.com/thameem/drop/internal/cli.Version=$(VERSION)

.PHONY: build install test vet check smoke clean

build:            ## build ./bin/drop
	go build -ldflags "$(LDFLAGS)" -o bin/drop ./cmd/drop

install:          ## build and install drop into a directory already on your PATH (override: BINDIR=...)
	VERSION="$(VERSION)" BINDIR="$(BINDIR)" sh scripts/install.sh

test:             ## unit and integration tests (with the race detector)
	go test -race -count=1 ./...

vet:
	go vet ./...

check: vet test smoke   ## everything

smoke: build      ## end-to-end test of the real binary (two instances on this machine)
	sh scripts/smoke.sh bin/drop

clean:
	rm -rf bin
