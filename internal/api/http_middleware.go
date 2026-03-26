package api

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/klauspost/compress/gzip"
	"github.com/segmentio/encoding/json"

	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
)

// metricsHumaMiddleware records Prometheus metrics for each huma request.
func metricsHumaMiddleware(ctx huma.Context, next func(huma.Context)) {
	start := time.Now()
	next(ctx)
	elapsed := time.Since(start)

	route := ctx.Operation().Path
	status := ctx.Status()
	if status == 0 {
		status = 200
	}

	httpRequestsTotal.WithLabelValues(ctx.Method(), route, strconv.Itoa(status)).Inc()
	httpRequestDuration.WithLabelValues(ctx.Method(), route).Observe(elapsed.Seconds())
}

var auditExcludedOps = map[string]struct{}{
	"patchCheckpoint":         {},
	"patchCheckpointVerbatim": {},
	"patchCheckpointDelta":    {},
	"saveJournalEntries":      {},
	"renewLease":              {},
	"postEvent":               {},
	"postEventsBatch":         {},
}

// auditHumaMiddleware logs structured audit entries for state-mutating API operations.
func auditHumaMiddleware(ctx huma.Context, next func(huma.Context)) {
	next(ctx)

	method := ctx.Method()
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return
	}

	op := ctx.Operation()
	if _, excluded := auditExcludedOps[op.OperationID]; excluded {
		return
	}

	actor := "unknown"
	if identity := auth.IdentityFromContext(ctx.Context()); identity != nil {
		actor = identity.UserName
	}

	status := ctx.Status()
	if status == 0 {
		status = 200
	}

	e := audit.Event{
		Actor:      actor,
		Action:     op.OperationID,
		Method:     method,
		Resource:   buildAuditResource(ctx),
		HTTPStatus: status,
		IP:         ctx.RemoteAddr(),
	}
	if status >= 400 {
		e.Warn("Audit Log: API Request")
	} else {
		e.Info("Audit Log: API Request")
	}
}

// buildAuditResource constructs a resource identifier from huma path params.
func buildAuditResource(ctx huma.Context) string {
	org := ctx.Param("orgName")
	if org == "" {
		return ""
	}
	project := ctx.Param("projectName")
	if project == "" {
		return org
	}
	stack := ctx.Param("stackName")
	if stack == "" {
		return org + "/" + project
	}
	return org + "/" + project + "/" + stack
}

// requestLogger logs each HTTP request with method, path, status, and latency.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		accessLog().Info("request", //nolint:gosec
			"log_type", "access",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"latency", time.Since(start),
			"remote_ip", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

// realIP extracts the real client IP from X-Real-Ip or X-Forwarded-For headers.
func realIP(next http.Handler, trustedProxies []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trustedProxies == nil || !isIPTrusted(r.RemoteAddr, trustedProxies) {
			next.ServeHTTP(w, r)
			return
		}
		if rip := r.Header.Get("X-Real-Ip"); rip != "" {
			r.RemoteAddr = rip
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				r.RemoteAddr = strings.TrimSpace(xff[:i])
			} else {
				r.RemoteAddr = xff
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isIPTrusted checks whether the remote address falls within any trusted CIDR.
func isIPTrusted(remoteAddr string, trusted []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range trusted {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// recoverer recovers from panics and returns a 500 Internal Server Error.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				slog.Error("panic recovered", "error", rvr, "method", r.Method, "path", r.URL.Path) //nolint:gosec
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets standard HTTP security headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

const maxDecompressedBody = 256 << 20

// writeJSONError writes a JSON error response with the given status code and message.
func writeJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message})
}

// gzipDecompressor transparently decompresses gzip request bodies.
func gzipDecompressor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid gzip body")
				return
			}
			defer gz.Close()
			limitReader := &io.LimitedReader{R: gz, N: maxDecompressedBody + 1}
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, limitReader); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid gzip body")
				return
			}
			if limitReader.N <= 0 {
				writeJSONError(w, http.StatusRequestEntityTooLarge, "decompressed body exceeds size limit")
				return
			}
			r.Body = io.NopCloser(&buf)
			r.ContentLength = int64(buf.Len())
			r.Header.Del("Content-Encoding")
		}
		next.ServeHTTP(w, r)
	})
}
