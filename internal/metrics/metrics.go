// Package metrics renders Prometheus text exposition without any
// dependency.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// sample is one series: a metric name with label set and value.
type sample struct {
	name, help, typ string
	labels          string
	v               float64
}

// Set is a point-in-time snapshot. It is rebuilt on every scrape, so there is no
// shared mutable state, no registration step and no dependency on a client library.
// Set is a point-in-time collection of metrics.
type Set struct{ s []sample }

func (m *Set) Counter(name, help string, v float64, labels ...string) {
	m.add(name, help, "counter", v, labels)
}

func (m *Set) Gauge(name, help string, v float64, labels ...string) {
	m.add(name, help, "gauge", v, labels)
}

// add formats labels as {k="v",...}. %q gives Prometheus-compatible quoting/escaping of the value.
func (m *Set) add(name, help, typ string, v float64, kv []string) {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, fmt.Sprintf(`%s=%q`, kv[i], kv[i+1]))
	}
	l := ""
	if len(parts) > 0 {
		l = "{" + strings.Join(parts, ",") + "}"
	}
	m.s = append(m.s, sample{name, help, typ, l, v})
}

// Write renders the set in the text exposition format. Series are sorted by name
// so all series of one metric are contiguous, and HELP/TYPE are written once per
// metric as the format requires.
func (m *Set) Write(w io.Writer) {
	seen := map[string]bool{}
	idx := make([]int, len(m.s))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return m.s[idx[a]].name < m.s[idx[b]].name })
	for _, i := range idx {
		s := m.s[i]
		if !seen[s.name] {
			seen[s.name] = true
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", s.name, s.help, s.name, s.typ)
		}
		fmt.Fprintf(w, "%s%s %g\n", s.name, s.labels, s.v)
	}
}

// Handler serves a fresh snapshot (collect is called on every scrape) with the standard Prometheus content type.
func Handler(collect func() *Set) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		collect().Write(w)
	})
}
