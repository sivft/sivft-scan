package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Rule struct {
	ID     string
	Name   string
	Action string
	Rate   float64
	Desc   string
	Match  func(*Event) bool
}

type RuleStat struct {
	Rule
	Matches    int
	Bytes      int64
	SavedBytes float64
	Samples    []string
}

type Report struct {
	TotalEvents  int
	TotalBytes   int64
	SavedBytes   float64
	ReductionPct float64
	RuleStats    []*RuleStat
}

type Event struct {
	Line      string
	Fields    map[string]any
	Service   string
	Severity  string
	Status    int
	SizeBytes int
}

var builtinRules = []Rule{
	dropRule("metric-request-id", "High-cardinality metric labels",
		"Drops metric events carrying request_id/trace_id/session_id labels that explode cardinality.",
		func(e *Event) bool {
			return hasAnyField(e, "request_id", "trace_id", "session_id", "requestId", "traceId")
		}),
	dropRule("debug-level-logs", "DEBUG/TRACE level logs",
		"Drops DEBUG and TRACE severity lines, the classic never-read volume.",
		func(e *Event) bool { return e.Severity == "debug" || e.Severity == "trace" }),
	dropRule("k8s-probe-logs", "Kubernetes probe logs",
		"Drops kubelet liveness/readiness/startup probe lines from kube-system.",
		func(e *Event) bool {
			return namespaceOf(e) == "kube-system" && containsFold(e.Line, "probe")
		}),
	dropRule("k8s-system-chatter", "kube-system namespace chatter",
		"Drops routine kube-system control-plane logs that are rarely queried.",
		func(e *Event) bool {
			return namespaceOf(e) == "kube-system" && (e.Severity == "" || e.Severity == "info" || e.Severity == "debug")
		}),
	dropRule("health-check", "Health check endpoint logs",
		"Drops requests to /health, /healthz, /readyz, /livez, /ping, /metrics and friends.",
		func(e *Event) bool {
			p := requestPath(e)
			if p == "" {
				return false
			}
			for _, h := range []string{"/healthz", "/health", "/readyz", "/livez", "/_health", "/ping", "/_ping", "/metrics", "/_status", "/heartbeat", "/readiness"} {
				if p == h || strings.HasPrefix(p, h+"/") || strings.HasPrefix(p, h+"?") {
					return true
				}
			}
			return false
		}),
	dropRule("static-assets-2xx", "Static asset 2xx requests",
		"Drops successful requests for css/js/images/fonts, which almost nobody queries.",
		func(e *Event) bool {
			return isStaticPath(requestPath(e)) && statusRange(e, 200, 299)
		}),
	sampleRule("nginx-2xx-access", "Successful ingress access logs", 0.01,
		"Keeps 1% of successful nginx/envoy/istio access logs for debuggability.",
		func(e *Event) bool {
			return statusRange(e, 200, 299) &&
				(strings.Contains(e.Service, "nginx") || strings.Contains(e.Service, "envoy") || strings.Contains(e.Service, "istio"))
		}),
	sampleRule("grpc-ok", "Successful gRPC calls", 0.01,
		"Keeps 1% of gRPC calls that returned OK.",
		func(e *Event) bool {
			if !containsFold(e.Line, "grpc") {
				return false
			}
			l := strings.ToLower(e.Line)
			return containsFold(l, "status 0") || containsFold(l, "code\":0") || containsFold(l, "code\": 0") || containsFold(l, "ok") || containsFold(l, "success")
		}),
	dropRule("redis-info", "Redis INFO-level chatter",
		"Drops routine Redis INFO lines (RDB snapshots, client connects, reconnects).",
		func(e *Event) bool {
			return strings.Contains(e.Service, "redis") && (e.Severity == "info" || e.Severity == "")
		}),
	dropRule("postgres-log", "PostgreSQL routine LOG messages",
		"Drops routine Postgres LOG lines (checkpoints, autovacuum, connections).",
		func(e *Event) bool {
			return strings.Contains(e.Service, "postgres") && (e.Severity == "info" || e.Severity == "notice" || e.Severity == "")
		}),
	dropRule("request-completed-2xx", "Framework 2xx completion lines",
		"Drops Rails/Spring-style 'Completed 200/201/204' lines.",
		func(e *Event) bool {
			return containsFold(e.Line, "completed 2") || (containsFold(e.Line, "rendered") && containsFold(e.Line, " 200 "))
		}),
	dropRule("spring-debug", "Spring framework DEBUG",
		"Drops Spring Boot DEBUG output, extremely verbose and rarely read.",
		func(e *Event) bool {
			return strings.Contains(e.Service, "spring") && e.Severity == "debug"
		}),
	dropRule("django-debug", "Django/WSGI DEBUG",
		"Drops Django DEBUG output.",
		func(e *Event) bool {
			return strings.Contains(e.Service, "django") && e.Severity == "debug"
		}),
	dropRule("docker-container-info", "Container runtime INFO chatter",
		"Drops routine Docker/containerd INFO lines.",
		func(e *Event) bool {
			return strings.Contains(e.Service, "docker") && (e.Severity == "info" || e.Severity == "debug")
		}),
	dropRule("systemd-info", "systemd routine INFO logs",
		"Drops routine systemd INFO lines (unit started/stopped, socket activity).",
		func(e *Event) bool {
			return strings.Contains(e.Service, "systemd") && e.Severity == "info"
		}),
	dropRule("scheduler-info", "Scheduler / cron routine INFO",
		"Drops routine cron/scheduler INFO lines (job started/finished/queued).",
		func(e *Event) bool {
			return (e.Severity == "info" || e.Severity == "debug") &&
				(containsFold(e.Line, "cron") || containsFold(e.Line, "scheduler") || containsFold(e.Line, "job "))
		}),
	dropRule("heartbeat-keepalive", "Heartbeat / keepalive traffic",
		"Drops heartbeat, keepalive, and ping traffic.",
		func(e *Event) bool {
			l := strings.ToLower(e.Line)
			return containsFold(l, "heartbeat") || containsFold(l, "keepalive") || containsFold(l, "keep-alive") ||
				containsFold(l, "ping request") || containsFold(l, "pong") || containsFold(l, "health ping")
		}),
	dropRule("audit-success", "Audit logs for successful actions",
		"Drops audit lines that record successful/allowed/passed actions.",
		func(e *Event) bool {
			l := strings.ToLower(e.Line)
			return (containsFold(l, "audit") || containsFold(l, "audit_log")) &&
				(containsFold(l, "success") || containsFold(l, "allowed") || containsFold(l, "passed"))
		}),
	dropRule("otel-collector-info", "OpenTelemetry collector internal INFO",
		"Drops routine OTel collector internal INFO/DEBUG lines.",
		func(e *Event) bool {
			return strings.Contains(e.Service, "otel") && (e.Severity == "info" || e.Severity == "debug")
		}),
	dropRule("http-2xx-plain", "Other successful HTTP 2xx logs",
		"Drops remaining 2xx HTTP logs not already caught by a specific rule.",
		func(e *Event) bool { return statusRange(e, 200, 299) }),
	sampleRule("loadbalancer-4xx-static", "4xx on static assets", 0.05,
		"Keeps 5% of 4xx responses for static assets, enough to catch trends.",
		func(e *Event) bool {
			return isStaticPath(requestPath(e)) && statusRange(e, 400, 499)
		}),
}

func dropRule(id, name, desc string, fn func(*Event) bool) Rule {
	return Rule{ID: id, Name: name, Action: "drop", Desc: desc, Match: fn}
}

func sampleRule(id, name string, rate float64, desc string, fn func(*Event) bool) Rule {
	return Rule{ID: id, Name: name, Action: "sample", Rate: rate, Desc: desc, Match: fn}
}

func parseEvent(line string) *Event {
	ev := &Event{Line: line, SizeBytes: len(line), Status: -1}
	var m map[string]any
	if json.Unmarshal([]byte(line), &m) == nil && m != nil {
		ev.Fields = m
	}
	ev.Service = detectService(ev)
	ev.Severity = detectSeverity(ev)
	ev.Status = detectStatus(ev)
	return ev
}

func detectService(ev *Event) string {
	for _, p := range []string{"service", "service.name", "serviceName", "app", "application", "container_name", "pod_name", "kubernetes.pod_name"} {
		if v, ok := getPath(ev.Fields, p); ok {
			if s := strings.ToLower(toStr(v)); s != "" {
				return s
			}
		}
	}
	line := strings.ToLower(ev.Line)
	for _, kw := range []string{"nginx", "envoy", "istio", "kubelet", "docker", "systemd", "postgres", "redis", "spring", "django", "rails", "otel", "cron"} {
		if strings.Contains(line, kw) {
			return kw
		}
	}
	return ""
}

func detectSeverity(ev *Event) string {
	for _, p := range []string{"level", "log.level", "loglevel", "severity", "levelname", "level_text"} {
		if v, ok := getPath(ev.Fields, p); ok {
			switch n := v.(type) {
			case float64:
				if s := otelSeverity(int(n)); s != "" {
					return s
				}
			case string:
				return normalizeLevel(n)
			}
		}
	}
	if v, ok := getPath(ev.Fields, "severitynumber"); ok {
		if n, ok := v.(float64); ok {
			if s := otelSeverity(int(n)); s != "" {
				return s
			}
		}
	}
	l := strings.ToLower(ev.Line)
	for _, kw := range []string{"fatal", "error", "warn", "info", "debug", "trace"} {
		if strings.Contains(l, " "+kw+" ") || strings.Contains(l, "="+kw+" ") || strings.Contains(l, "\""+kw+"\"") {
			return kw
		}
	}
	return ""
}

func normalizeLevel(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	switch l {
	case "trace", "verbose":
		return "trace"
	case "debug":
		return "debug"
	case "info", "information", "notice", "log":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error", "err", "severe":
		return "error"
	case "fatal", "critical", "alert", "emergency", "panic":
		return "fatal"
	}
	return ""
}

func otelSeverity(n int) string {
	switch {
	case n >= 1 && n <= 4:
		return "trace"
	case n >= 5 && n <= 8:
		return "debug"
	case n >= 9 && n <= 12:
		return "info"
	case n >= 13 && n <= 16:
		return "warn"
	case n >= 17 && n <= 20:
		return "error"
	case n >= 21 && n <= 24:
		return "fatal"
	}
	return ""
}

func detectStatus(ev *Event) int {
	for _, p := range []string{"http.status_code", "httpStatusCode", "status", "status_code", "statusCode", "http.response.status_code", "response.status"} {
		if v, ok := getPath(ev.Fields, p); ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case string:
				if s, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
					return s
				}
			}
		}
	}
	l := ev.Line
	if strings.Contains(l, "status") || strings.Contains(l, "GET ") || strings.Contains(l, "POST ") ||
		strings.Contains(l, "PUT ") || strings.Contains(l, "DELETE ") || strings.Contains(l, "HTTP/") {
		for i := 0; i+2 < len(l); i++ {
			if l[i] < '1' || l[i] > '5' {
				continue
			}
			if l[i+1] < '0' || l[i+1] > '9' || l[i+2] < '0' || l[i+2] > '9' {
				continue
			}
			before := i == 0 || l[i-1] == ' ' || l[i-1] == ':' || l[i-1] == '='
			after := i+3 == len(l) || l[i+3] == ' ' || l[i+3] == '\t' || l[i+3] == ',' || l[i+3] == ']' || l[i+3] == '}'
			if before && after {
				if s, err := strconv.Atoi(l[i : i+3]); err == nil && s >= 100 && s <= 599 {
					return s
				}
			}
		}
	}
	return -1
}

func getPath(f map[string]any, path string) (any, bool) {
	if v, ok := f[path]; ok {
		return v, true
	}
	var cur any = f
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func hasAnyField(e *Event, paths ...string) bool {
	for _, p := range paths {
		if _, ok := getPath(e.Fields, p); ok {
			return true
		}
	}
	return false
}

func toStr(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(n)
	}
	return fmt.Sprintf("%v", v)
}

func namespaceOf(ev *Event) string {
	for _, p := range []string{"kubernetes.namespace_name", "k8s.namespace.name", "k8s.namespace_name", "namespace", "kubernetes.namespace"} {
		if v, ok := getPath(ev.Fields, p); ok {
			if s := strings.ToLower(toStr(v)); s != "" {
				return s
			}
		}
	}
	if strings.Contains(strings.ToLower(ev.Line), "kube-system") {
		return "kube-system"
	}
	return ""
}

func statusRange(e *Event, lo, hi int) bool {
	return e.Status >= lo && e.Status <= hi
}

func requestPath(e *Event) string {
	for _, p := range []string{"http.url", "url", "path", "request.path", "request_path", "uri", "request_uri", "http.request.path"} {
		if v, ok := getPath(e.Fields, p); ok {
			s := toStr(v)
			if strings.HasPrefix(s, "/") {
				return strings.ToLower(s)
			}
		}
	}
	l := strings.ToLower(e.Line)
	for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD "} {
		idx := strings.Index(l, m)
		if idx >= 0 {
			rest := l[idx+len(m):]
			if j := strings.IndexAny(rest, " ?\"'"); j > 0 && strings.HasPrefix(rest, "/") {
				return rest[:j]
			}
		}
	}
	for _, f := range strings.Fields(l) {
		if strings.HasPrefix(f, "/") {
			return f
		}
	}
	return ""
}

var staticExts = []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif"}

func isStaticPath(p string) bool {
	if p == "" {
		return false
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
