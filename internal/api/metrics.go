package api

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pulumi_backend_http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"method", "route", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pulumi_backend_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)

	stackOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pulumi_backend_stack_operations_total",
			Help: "Total number of stack operations.",
		},
		[]string{"operation"},
	)

	updateDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pulumi_backend_update_duration_seconds",
			Help:    "Duration of update lifecycle (start to complete) in seconds.",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800},
		},
		[]string{"kind", "status"},
	)

	checkpointBytes = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pulumi_backend_checkpoint_bytes",
			Help:    "Size of checkpoint payloads in bytes.",
			Buckets: prometheus.ExponentialBuckets(1024, 4, 8), // 1KB, 4KB, 16KB, 64KB, 256KB, 1MB, 4MB, 16MB
		},
		[]string{"mode"},
	)
)

func init() {
	prometheus.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		stackOperationsTotal,
		updateDuration,
		checkpointBytes,
	)
}

// RegisterActiveUpdatesGauge registers a gauge that tracks active updates from the engine.
func RegisterActiveUpdatesGauge(countFn func() float64) {
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "pulumi_backend_active_updates",
			Help: "Number of currently active (in-progress) updates.",
		},
		countFn,
	))
}

// MetricsHandler returns the Prometheus metrics HTTP handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
