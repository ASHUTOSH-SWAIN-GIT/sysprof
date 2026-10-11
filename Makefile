BIN := bin/sysprof

.PHONY: build build-linux generate demo test

build:
	go build -o $(BIN) ./cmd/sysprof

# Cross compile for a Linux VM (set GOARCH=amd64 for Intel hosts).
build-linux:
	GOOS=linux GOARCH=$${GOARCH:-arm64} go build -o $(BIN)-linux ./cmd/sysprof

# Recompile the bpf/*.c programs into Go bindings. Needs clang, llvm and
# libbpf-dev on Linux; on a Mac this runs inside a container because Apple
# clang has no BPF backend.
GEN_PKGS := internal/collector internal/shield internal/sockbypass

generate:
ifeq ($(shell uname -s),Linux)
	for p in $(GEN_PKGS); do (cd $$p && go generate ./...) || exit 1; done
else
	docker run --rm -v "$$PWD":/src -w /src golang:1.26 sh -c \
	  'apt-get update -qq && apt-get install -y -qq clang llvm libbpf-dev linux-libc-dev && \
	   export GOFLAGS=-buildvcs=false && for p in $(GEN_PKGS); do (cd $$p && go generate ./...) || exit 1; done'
endif

# Web UI with generated data, no Linux needed.
demo: build
	$(BIN) serve --fake

test:
	go test ./...
