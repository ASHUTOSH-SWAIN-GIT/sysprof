BIN := bin/sysprof

.PHONY: build build-linux generate demo test

build:
	go build -o $(BIN) ./cmd/sysprof

# Cross compile for a Linux VM (set GOARCH=amd64 for Intel hosts).
build-linux:
	GOOS=linux GOARCH=$${GOARCH:-arm64} go build -o $(BIN)-linux ./cmd/sysprof

# Recompile bpf/syscall_latency.c into Go bindings. Needs clang on Linux; on a
# Mac this runs inside a container because Apple clang has no BPF backend.
generate:
ifeq ($(shell uname -s),Linux)
	cd internal/collector && go generate ./...
else
	docker run --rm -v "$$PWD":/src -w /src/internal/collector golang:1.26 sh -c \
	  'apt-get update -qq && apt-get install -y -qq clang llvm && GOFLAGS=-buildvcs=false go generate ./...'
endif

# Web UI with generated data, no Linux needed.
demo: build
	$(BIN) serve --fake

test:
	go test ./...
