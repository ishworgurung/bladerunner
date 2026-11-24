// Module path matches the GitHub repository.
module github.com/ishworgurung/bladerunner

// Minimum toolchain. 1.21 is needed for encoding/binary.NativeEndian and log/slog.
go 1.27

// Direct dependencies only; `make deps` (go mod tidy) fills in go.sum and indirect requirements.
require (
	// Pure-Go BPF loader/library (no cgo, no libbpf at runtime).
	github.com/cilium/ebpf v0.22.0
	// Raw syscalls: CLOCK_MONOTONIC and mounting bpffs.
	golang.org/x/sys v0.50.0
	// YAML parsing for the config file (supports strict unknown-key rejection).
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/redis/go-redis/v9 v9.7.3 // indirect
	golang.org/x/sync v0.25.0 // indirect
)
