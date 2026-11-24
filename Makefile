# Build, test and run targets. `make help`-style summary: see the .PHONY list.
# bladerunner - XDP DDoS mitigation
# Tool overrides: `make CLANG=clang-18 GO=go1.22`.
GO      ?= go
CLANG   ?= clang
# Map uname -m to the kernel's arch name for clang's -D__TARGET_ARCH_* (used by
# libbpf's bpf_tracing.h macros; harmless for this program but keeps it portable).
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
# Debian/Ubuntu keep arch-specific headers (asm/types.h ...) in a multiarch dir.
MULTIARCH := $(shell uname -m)-linux-gnu
# Version string stamped into the binary from git (falls back to "dev" outside a checkout).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Source and output of the BPF object. The object lands inside internal/bpf because go:embed can only embed files from its own package directory.
BPF_SRC := bpf/bladerunner.bpf.c
BPF_OBJ := internal/bpf/bladerunner.bpf.o

# Targets that are commands, not files.
.PHONY: all bpf build deps test test-unit e2e vet fmt clean install dist vmtest

# Default target.
all: build

# -O2 is required (the verifier rejects unoptimised code), -g emits BTF so maps
# and the program are described to the kernel, -target bpf selects the BPF backend.
# The BPF object is embedded into the Go binary, so it must exist before go build.
bpf: $(BPF_OBJ)
$(BPF_OBJ): $(BPF_SRC) bpf/bladerunner_common.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(MULTIARCH) -Ibpf -c $(BPF_SRC) -o $@

# Resolve and record Go module versions (writes go.sum). Needs network access to the module proxy.
deps:
	$(GO) mod tidy

# The object must exist BEFORE `go build` because it is embedded into the binary.
build: bpf
	$(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o bladerunner ./cmd/bladerunner

# Pure-Go tests (no privileges needed).
# Pure-Go tests (no privileges needed).
test-unit:
	$(GO) test ./internal/detect ./internal/config ./internal/metrics

# BLADERUNNER_REQUIRE_BPF=1 turns "cannot load BPF" from a skip into a failure, so CI can never
# go green by silently skipping the kernel tests.
# Everything, including verifier-load and BPF_PROG_TEST_RUN tests. Needs root; those tests skip themselves when BPF cannot be loaded.
# Everything, including verifier-load and BPF_PROG_TEST_RUN tests (needs root;
# those tests skip themselves when BPF cannot be loaded).
test: bpf
	sudo -E env "PATH=$$PATH" BLADERUNNER_REQUIRE_BPF=1 $(GO) test -count=1 ./...

# Loopback smoke test: attaches to lo in generic mode for ~30s.
# Loopback smoke test: attaches to lo in generic mode for ~30s (needs root).
e2e: build
	sudo ./scripts/e2e_lo.sh

# go vet needs the embedded object to exist, hence the dependency on bpf.
vet: bpf
	$(GO) vet ./...

# Format all Go sources.
fmt:
	gofmt -w cmd internal

# Install the binary system-wide.
install: build
	install -m 0755 bladerunner /usr/local/bin/bladerunner

# Remove build outputs.
clean:
	rm -f bladerunner $(BPF_OBJ)

# Cross-compile the daemon for x86-64, aarch64 and riscv64 into dist/. The BPF
# object is architecture-independent bytecode, so it is built once. cilium/ebpf is
# pure Go, so CGO is off and no C cross-compiler is needed.
dist: bpf
	@mkdir -p dist
	@for a in amd64 arm64 riscv64; do \
		echo "building dist/bladerunner-linux-$$a"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" -o dist/bladerunner-linux-$$a ./cmd/bladerunner || exit 1; \
	done

# Boot QEMU VMs (x86-64, aarch64, riscv64), load the binaries onto their NICs and
# test them from this host. No root needed. VMARCH="x86_64" limits it to one.
vmtest: dist
	./scripts/vmtest.sh $(VMARCH)
