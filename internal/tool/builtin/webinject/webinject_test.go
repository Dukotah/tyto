package webinject

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func vulnServer() *httptest.Server {
	mux := http.NewServeMux()
	// Reflects the q param UNENCODED, and emits a SQL error when it sees a quote.
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		body := "<html>results for: " + q + "</html>"
		if strings.Contains(q, "'") {
			body += "<br>You have an error in your SQL syntax; check the manual"
		}
		_, _ = w.Write([]byte(body))
	})
	// Properly encodes output: not vulnerable.
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>" + html.EscapeString(r.URL.Query().Get("q")) + "</html>"))
	})
	// Naive file reader: a traversal sequence reaching /etc/passwd leaks it.
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "etc/passwd") || strings.Contains(file, "etc%2fpasswd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		_, _ = w.Write([]byte("file not found"))
	})
	// Naive shell-out: appending `;id` (etc.) runs the unix id command.
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		body := "PING " + cmd + "\n"
		if strings.Contains(cmd, "id") {
			body += "uid=0(root) gid=0(root) groups=0(root)\n"
		}
		_, _ = w.Write([]byte(body))
	})
	return httptest.NewServer(mux)
}

func findingTitles(res action.Result) map[string]state.Severity {
	m := map[string]state.Severity{}
	for _, f := range res.Findings {
		m[f.Title] = f.Severity
	}
	return m
}

func TestWebinjectDetectsXSSAndSQLi(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL + "/search?q=test"})
	if err != nil {
		t.Fatal(err)
	}
	titles := findingTitles(res)
	if titles["Reflected XSS in parameter q"] != state.SeverityHigh {
		t.Errorf("expected HIGH reflected-XSS finding; got %v", titles)
	}
	if titles["SQL injection (error-based) in parameter q"] != state.SeverityHigh {
		t.Errorf("expected HIGH SQLi finding; got %v", titles)
	}
}

func TestWebinjectDetectsPathTraversal(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a4", Target: srv.URL + "/download?file=report.txt"})
	if err != nil {
		t.Fatal(err)
	}
	titles := findingTitles(res)
	if titles["Path traversal in parameter file"] != state.SeverityHigh {
		t.Errorf("expected HIGH path-traversal finding; got %v", titles)
	}
}

func TestWebinjectDetectsCommandInjection(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a5", Target: srv.URL + "/ping?cmd=8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	titles := findingTitles(res)
	if titles["Command injection in parameter cmd"] != state.SeverityCritical {
		t.Errorf("expected CRITICAL command-injection finding; got %v", titles)
	}
}

func TestWebinjectNoFalsePositiveOnSafeEndpoint(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL + "/safe?q=test"})
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "XSS") || strings.Contains(f.Title, "SQL injection") ||
			strings.Contains(f.Title, "Path traversal") || strings.Contains(f.Title, "Command injection") {
			t.Errorf("safe endpoint should not produce injection findings, got %q", f.Title)
		}
	}
}

func TestWebinjectNoParams(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	res, _ := New().Execute(context.Background(), action.Action{ID: "a3", Target: srv.URL + "/search"})
	if len(res.Findings) != 1 || res.Findings[0].Title != "No query parameters to test" {
		t.Fatalf("expected a single 'no parameters' note, got %+v", res.Findings)
	}
}
