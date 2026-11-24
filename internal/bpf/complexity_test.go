package bpf

import (
	"bytes"
	"regexp"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
)

// maxVerifierInsns is the regression budget for verifier work. The kernel
// aborts a program at 1,000,000 processed instructions, and different kernel
// versions prune differently, so the budget is set far below that limit to keep
// a comfortable margin on kernels other than the one this was measured on.
const maxVerifierInsns = 100000

// TestVerifierComplexity loads the program with verifier statistics enabled and
// fails if the verifier had to process too many instructions. This exists
// because the fingerprint-rule loop once passed on one kernel and was rejected
// ("BPF program is too large") on another; a budget catches that class of
// regression before it reaches CI or production.
func TestVerifierComplexity(t *testing.T) {
	o := load(t) // ensures BPF is usable (skips/fails consistently with the others)
	o.Close()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
	if err != nil {
		t.Fatal(err)
	}
	var objs Objects
	opts := ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer objs.Close()

	// The stats line looks like: "processed 12345 insns (limit 1000000) ..."
	m := regexp.MustCompile(`processed (\d+) insns`).FindStringSubmatch(objs.Prog.VerifierLog)
	if m == nil {
		t.Skip("kernel did not report verifier statistics")
	}
	n, _ := strconv.Atoi(m[1])
	t.Logf("verifier processed %d instructions (budget %d, kernel limit 1,000,000)", n, maxVerifierInsns)
	if n > maxVerifierInsns {
		t.Fatalf("verifier processed %d insns, over budget %d", n, maxVerifierInsns)
	}
}
