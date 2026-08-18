package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectSeverity(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"json info", `{"level":"INFO","service":"nginx"}`, "info"},
		{"json error", `{"level":"ERROR","service":"x"}`, "error"},
		{"json warning alias", `{"level":"warning"}`, "warn"},
		{"json trace", `{"level":"trace"}`, "trace"},
		{"otel severity error", `{"severitynumber":17,"message":"x"}`, "error"},
		{"otel severity debug", `{"severitynumber":6,"message":"x"}`, "debug"},
		{"otel severity out of range", `{"severitynumber":99,"message":"x"}`, ""},
		{"plain info token", "2026-08-18 10:00:00 INFO  processing", "info"},
		{"plain fatal token", "2026-08-18 10:00:00 FATAL  aborting", "fatal"},
		{"no level", `{"message":"no level here"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseEvent(tt.line)
			if ev.Severity != tt.want {
				t.Fatalf("severity = %q, want %q (line %q)", ev.Severity, tt.want, tt.line)
			}
		})
	}
}

func TestDetectStatus(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{"json nested code", `{"http.status_code":200,"message":"ok"}`, 200},
		{"json status", `{"status":404,"message":"x"}`, 404},
		{"json string code", `{"httpStatusCode":"201","message":"x"}`, 201},
		{"no status field", `{"level":"info","message":"nothing"}`, -1},
		{"plaintext 200", `10.0.0.1 - - "GET / HTTP/1.1" 200 1024`, 200},
		{"plaintext 503", `10.0.0.1 - - "GET /x HTTP/1.1" 503 12`, 503},
		{"error log no status", `{"level":"error","msg":"boom"}`, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseEvent(tt.line)
			if ev.Status != tt.want {
				t.Fatalf("status = %d, want %d (line %q)", ev.Status, tt.want, tt.line)
			}
		})
	}
}

func TestDetectService(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"json service", `{"service":"nginx","level":"info"}`, "nginx"},
		{"json serviceName", `{"serviceName":"auth","level":"info"}`, "auth"},
		{"plaintext keyword", "Aug 18 10:00:00 host postgres: LOG: checkpoint", "postgres"},
		{"no service", `{"message":"hello"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseEvent(tt.line)
			if ev.Service != tt.want {
				t.Fatalf("service = %q, want %q (line %q)", ev.Service, tt.want, tt.line)
			}
		})
	}
}

func TestRequestPath(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"json path", `{"path":"/healthz","status":200}`, "/healthz"},
		{"json http url", `{"http.url":"/api/orders","status":201}`, "/api/orders"},
		{"plaintext quoted", `nginx: 10.0.0.1 - - "GET /assets/app.js HTTP/1.1" 200`, "/assets/app.js"},
		{"none", `{"level":"info","message":"x"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseEvent(tt.line)
			if got := requestPath(ev); got != tt.want {
				t.Fatalf("requestPath = %q, want %q (line %q)", got, tt.want, tt.line)
			}
		})
	}
}

func TestFirstMatchingRule(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"debug level", `{"level":"DEBUG","message":"x"}`, "debug-level-logs"},
		{"trace level", `{"level":"TRACE","message":"x"}`, "debug-level-logs"},
		{"health check", `{"level":"info","path":"/healthz","status":200}`, "health-check"},
		{"readiness check", `{"level":"info","path":"/readyz","status":200}`, "health-check"},
		{"static asset 2xx", `{"level":"info","path":"/static/app.js","status":200}`, "static-assets-2xx"},
		{"nginx 2xx", `{"level":"info","service":"nginx","status":200}`, "nginx-2xx-access"},
		{"k8s probe", `{"level":"info","namespace":"kube-system","message":"Readiness probe failed"}`, "k8s-probe-logs"},
		{"k8s chatter", `{"level":"info","namespace":"kube-system","message":"runtime network ready"}`, "k8s-system-chatter"},
		{"high cardinality label", `{"level":"info","request_id":"abc","message":"x"}`, "metric-request-id"},
		{"redis info", `{"level":"INFO","service":"redis","message":"DB 0: 42 keys"}`, "redis-info"},
		{"postgres log", `{"level":"INFO","service":"postgres","message":"checkpoint starting"}`, "postgres-log"},
		{"completed 200", `{"level":"INFO","service":"api","message":"Completed 200 OK"}`, "request-completed-2xx"},
		{"heartbeat", `{"level":"INFO","message":"heartbeat sent"}`, "heartbeat-keepalive"},
		{"scheduler", `{"level":"INFO","message":"job 'nightly-backup' started"}`, "scheduler-info"},
		{"audit success", `{"level":"INFO","message":"audit success: user 42 updated role"}`, "audit-success"},
		{"plain health", `nginx: 10.0.0.1 - - "GET /healthz HTTP/1.1" 200`, "health-check"},
		{"plain 2xx kept", `nginx: 10.0.0.1 - - "POST /api/orders HTTP/1.1" 201 12`, "nginx-2xx-access"},
		{"error kept", `{"level":"ERROR","message":"boom"}`, ""},
		{"warn kept", `{"level":"WARN","message":"cache miss"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstMatch(tt.line); got != tt.want {
				t.Fatalf("rule = %q, want %q (line %q)", got, tt.want, tt.line)
			}
		})
	}
}

func TestAnalyzeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.jsonl")
	content := strings.Join([]string{
		`{"level":"DEBUG","service":"x","message":"parse"}`,
		`{"level":"ERROR","service":"x","message":"boom"}`,
		`{"level":"INFO","service":"nginx","status":200,"message":"ok"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := analyzeFile(path, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalEvents != 3 {
		t.Fatalf("TotalEvents = %d, want 3", rep.TotalEvents)
	}
	if rep.SavedBytes <= 0 {
		t.Fatal("expected some savings from the DEBUG line")
	}
	if rep.ReductionPct <= 0 || rep.ReductionPct >= 100 {
		t.Fatalf("ReductionPct = %.2f, want (0,100)", rep.ReductionPct)
	}
}

func TestEmptyAndBlankFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := analyzeFile(empty, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalEvents != 0 || rep.TotalBytes != 0 {
		t.Fatalf("empty file: events=%d bytes=%d, want 0/0", rep.TotalEvents, rep.TotalBytes)
	}

	blank := filepath.Join(dir, "blank.log")
	if err := os.WriteFile(blank, []byte("\n\n  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = analyzeFile(blank, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalEvents != 0 {
		t.Fatalf("blank file: events=%d, want 0", rep.TotalEvents)
	}
}

func TestLongLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long.log")
	content := `{"level":"INFO","message":"short"}` + "\n" + strings.Repeat("x", 200000) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := analyzeFile(path, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalEvents != 2 {
		t.Fatalf("TotalEvents = %d, want 2 (long lines must not crash)", rep.TotalEvents)
	}
}

func TestComma(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{-1, "-1"},
	}
	for _, tt := range tests {
		if got := comma(tt.in); got != tt.want {
			t.Fatalf("comma(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
	}
	for _, tt := range tests {
		if got := humanBytes(tt.in); got != tt.want {
			t.Fatalf("humanBytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPctOf(t *testing.T) {
	tests := []struct {
		a, b float64
		want float64
	}{
		{0, 0, 0},
		{50, 100, 50},
		{10, 200, 5},
	}
	for _, tt := range tests {
		if got := pctOf(tt.a, tt.b); got != tt.want {
			t.Fatalf("pctOf(%v,%v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func firstMatch(line string) string {
	rep := &Report{}
	for _, r := range builtinRules {
		rep.RuleStats = append(rep.RuleStats, &RuleStat{Rule: r})
	}
	rep.process(line)
	for _, st := range rep.RuleStats {
		if st.Matches > 0 {
			return st.ID
		}
	}
	return ""
}
