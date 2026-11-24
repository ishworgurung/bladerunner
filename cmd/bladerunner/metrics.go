package main

import (
	"net/http"

	"github.com/ishworgurung/bladerunner/internal/metrics"
)

// metricsHTTP adapts the engine's collector to an http.Handler. Kept in its own file so main.go need not import the metrics package directly.
func metricsHTTP(f func() *metrics.Set) http.Handler { return metrics.Handler(f) }
