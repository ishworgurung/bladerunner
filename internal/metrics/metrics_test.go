package metrics

import (
	"strings"
	"testing"
)

// Series of one metric share a single HELP/TYPE header and labels are rendered correctly.
func TestRender(t *testing.T) {
	var s Set
	s.Counter("bladerunner_packets_total", "Packets.", 5, "reason", "pass")
	s.Counter("bladerunner_packets_total", "Packets.", 2, "reason", "rate_limit")
	s.Gauge("bladerunner_attack", "Attack flag.", 1)
	var b strings.Builder
	s.Write(&b)
	out := b.String()
	if strings.Count(out, "# TYPE bladerunner_packets_total counter") != 1 {
		t.Error("header must appear once per metric")
	}
	for _, want := range []string{`bladerunner_packets_total{reason="pass"} 5`, `bladerunner_packets_total{reason="rate_limit"} 2`, "bladerunner_attack 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
