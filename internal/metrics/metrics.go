package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds Prometheus collectors.
type Metrics struct {
	Requests *prometheus.CounterVec
	Latency  *prometheus.HistogramVec
}

// New registers default metrics.
func New() *Metrics {
	return &Metrics{
		Requests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "gap_http_requests_total",
			Help: "Total HTTP requests handled by grok-auth-proxy",
		}, []string{"method", "path", "status"}),
		Latency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "gap_http_request_duration_seconds",
			Help:    "HTTP request latency",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path"}),
	}
}

// Middleware records request metrics.
func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		status := strconv.Itoa(c.Writer.Status())
		m.Requests.WithLabelValues(c.Request.Method, path, status).Inc()
		m.Latency.WithLabelValues(c.Request.Method, path).Observe(time.Since(start).Seconds())
	}
}

// Handler returns the Prometheus scrape handler.
func Handler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
